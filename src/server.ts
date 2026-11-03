/**
 * Thin HTTP adapter over the pure proxy handler (src/proxy.ts).
 *
 * Responsibilities kept here, and only here: reading the request body
 * (1 MB cap -> 413), JSON parsing (malformed -> 400), header normalisation
 * and JSON responses. All firewall decisions live in the handler, which is
 * why the handler — not a socket — is what the tests exercise.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  createProxyHandler,
  type ProxyOptions,
  type ProxyStats,
} from "./proxy.js";

const MAX_BODY_BYTES = 1_000_000;

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createProxyServer(
  options: ProxyOptions = {},
): { server: Server; stats: ProxyStats } {
  const { handle, stats } = createProxyHandler(options);
  const server = createServer(async (req, res) => {
    try {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === "string") headers[key.toLowerCase()] = value;
      }
      let body: unknown;
      const raw = await readBody(req);
      if (raw.trim() !== "") {
        try {
          body = JSON.parse(raw);
        } catch {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "request body must be valid JSON" }));
          return;
        }
      }
      const url = new URL(req.url ?? "/", "http://localhost");
      const result = await handle({
        method: req.method ?? "GET",
        path: url.pathname,
        headers,
        body,
      });
      res.writeHead(result.status, { "content-type": "application/json" });
      res.end(JSON.stringify(result.body));
    } catch (err) {
      const status = err instanceof Error && err.message === "body too large" ? 413 : 500;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : "internal error" }));
    }
  });
  return { server, stats };
}
