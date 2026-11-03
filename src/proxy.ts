/**
 * Proxy server core: a pure, socket-free request handler over the scanner,
 * output guard and policy engine, plus an in-memory stats counter.
 *
 * The handler takes a parsed request and returns a status + JSON body, so
 * it is unit-testable without binding a socket (see src/server.ts for the
 * thin HTTP adapter that parses bodies and enforces the 1 MB limit).
 *
 * Endpoints:
 *   GET  /health       -> { status: "ok", version }
 *   GET  /v1/policies  -> the three built-in policies
 *   GET  /v1/stats     -> request counters (see ProxyStats)
 *   POST /v1/scan      -> { prompt } -> ScanResult
 *   POST /v1/guard     -> { text } -> GuardResult + redacted text
 *   POST /v1/chat      -> { prompt, output? } -> policy decision; when no
 *                          output is supplied and an upstream is configured,
 *                          the upstream is called and its reply guarded.
 *                          A blocked input never reaches the upstream.
 */
import { redactOutput, scanOutput, type GuardOptions } from "./output.js";
import {
  DEFAULT_POLICY,
  MONITOR_POLICY,
  STRICT_POLICY,
  applyPolicy,
  type Policy,
  type PolicyDecision,
} from "./policy.js";
import { scanPrompt } from "./scanner.js";
import type { ScannerOptions } from "./types.js";

// Kept in sync with package.json; importing it from index.ts would create
// an import cycle (index re-exports this module).
const VERSION = "0.1.0";

export interface ProxyRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  status: number;
  body: unknown;
}

export interface ProxyStats {
  requests: number;
  scans: number;
  guards: number;
  chats: number;
  byAction: Record<string, number>;
}

export interface ProxyOptions {
  policy?: Policy;
  scannerOptions?: ScannerOptions;
  guardOptions?: GuardOptions;
  /** Model stand-in: called only for inputs that are not blocked. */
  upstream?: (prompt: string) => Promise<string> | string;
  /** When set, every request must carry `x-api-key` with this value. */
  apiKey?: string;
}

const POLICIES: Record<string, Policy> = {
  monitor: MONITOR_POLICY,
  default: DEFAULT_POLICY,
  strict: STRICT_POLICY,
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function badRequest(message: string): ProxyResponse {
  return { status: 400, body: { error: message } };
}

export function createProxyHandler(options: ProxyOptions = {}): {
  handle: (req: ProxyRequest) => Promise<ProxyResponse>;
  stats: ProxyStats;
} {
  const policy = options.policy ?? DEFAULT_POLICY;
  const stats: ProxyStats = {
    requests: 0,
    scans: 0,
    guards: 0,
    chats: 0,
    byAction: { allow: 0, flag: 0, block: 0, redact: 0 },
  };

  async function handle(req: ProxyRequest): Promise<ProxyResponse> {
    stats.requests += 1;
    const path = req.path.split("?")[0]!.replace(/\/$/, "") || "/";
    const method = req.method.toUpperCase();

    if (options.apiKey !== undefined) {
      const supplied = req.headers?.["x-api-key"];
      if (supplied !== options.apiKey) {
        return { status: 401, body: { error: "unauthorized" } };
      }
    }

    if (method === "GET" && path === "/health") {
      return { status: 200, body: { status: "ok", version: VERSION } };
    }
    if (method === "GET" && path === "/v1/policies") {
      return { status: 200, body: { policies: Object.values(POLICIES) } };
    }
    if (method === "GET" && path === "/v1/stats") {
      return { status: 200, body: { ...stats } };
    }

    const knownPaths = ["/v1/scan", "/v1/guard", "/v1/chat", "/v1/chat/completions"];
    if (knownPaths.includes(path) && method !== "POST") {
      return { status: 405, body: { error: "method not allowed" } };
    }
    if (method !== "POST" || !knownPaths.includes(path)) {
      return { status: 404, body: { error: "not found" } };
    }
    if (!isObject(req.body)) {
      return badRequest("request body must be a JSON object");
    }

    if (path === "/v1/scan") {
      if (typeof req.body.prompt !== "string") {
        return badRequest("prompt must be a string");
      }
      stats.scans += 1;
      return { status: 200, body: scanPrompt(req.body.prompt, options.scannerOptions) };
    }

    if (path === "/v1/guard") {
      if (typeof req.body.text !== "string") {
        return badRequest("text must be a string");
      }
      stats.guards += 1;
      const guard = scanOutput(req.body.text, options.guardOptions);
      return {
        status: 200,
        body: { ...guard, redacted: redactOutput(req.body.text, guard).text },
      };
    }

    // POST /v1/chat and POST /v1/chat/completions share the decision
    // flow; completions just takes the last user message as the prompt and
    // wraps the answer in the OpenAI-style choices shape.
    let prompt: string | undefined;
    let suppliedOutput: string | undefined;
    if (path === "/v1/chat/completions") {
      const messages = req.body.messages;
      if (!Array.isArray(messages) || messages.length === 0) {
        return badRequest("messages must be a non-empty array");
      }
      const userMessages = messages.filter(
        (m) => isObject(m) && m.role === "user" && typeof m.content === "string",
      ) as { content: string }[];
      if (userMessages.length === 0) {
        return badRequest("messages must include a user message with string content");
      }
      prompt = userMessages[userMessages.length - 1]!.content;
    } else {
      prompt = req.body.prompt as string | undefined;
      suppliedOutput = req.body.output as string | undefined;
    }
    if (typeof prompt !== "string" || prompt.trim() === "") {
      return badRequest("prompt must be a non-empty string");
    }
    if (suppliedOutput !== undefined && typeof suppliedOutput !== "string") {
      return badRequest("output must be a string when provided");
    }
    const scan = scanPrompt(prompt, options.scannerOptions);
    if (scan.verdict === "block") {
      const early = applyPolicy(scan, undefined, undefined, policy);
      if (early.action === "block") {
        stats.chats += 1;
        stats.byAction.block += 1;
        return { status: 403, body: { decision: early, scan } };
      }
    }
    let outputText: string;
    if (typeof suppliedOutput === "string") {
      outputText = suppliedOutput;
    } else if (options.upstream) {
      try {
        outputText = await options.upstream(prompt);
      } catch {
        return { status: 502, body: { error: "upstream failed" } };
      }
    } else {
      return badRequest("output is required when no upstream is configured");
    }
    const guard = scanOutput(outputText, options.guardOptions);
    const decision: PolicyDecision = applyPolicy(scan, outputText, guard, policy);
    stats.chats += 1;
    stats.byAction[decision.action] += 1;
    if (path === "/v1/chat/completions") {
      return {
        status: decision.action === "block" ? 403 : 200,
        body: {
          choices:
            decision.action === "block"
              ? []
              : [{ message: { role: "assistant", content: decision.output } }],
          decision,
          scan,
          guard,
        },
      };
    }
    return {
      status: decision.action === "block" ? 403 : 200,
      body: { decision, scan, guard, output: decision.output },
    };
  }

  return { handle, stats };
}

export { POLICIES };
