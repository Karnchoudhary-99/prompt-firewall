#!/usr/bin/env node
/**
 * pf-proxy: run the firewall as an HTTP proxy server.
 *
 *   npm run proxy -- --port 3000
 *   npm run proxy -- --policy strict --port 3000 --upstream-echo
 *   PF_API_KEY=secret npm run proxy -- --api-key-env
 *
 * --upstream-echo stands in for a real model (it echoes the prompt) so the
 * chat endpoint can be exercised without an LLM key. Without it, /v1/chat
 * requires an `output` field in the request body.
 * Exit code 1 = usage error.
 */
import { createProxyServer } from "./server.js";
import {
  DEFAULT_POLICY,
  MONITOR_POLICY,
  STRICT_POLICY,
  type Policy,
} from "./policy.js";

const POLICIES: Record<string, Policy> = {
  monitor: MONITOR_POLICY,
  default: DEFAULT_POLICY,
  strict: STRICT_POLICY,
};

function usage(): never {
  console.error(
    "Usage: pf-proxy [--port N] [--policy monitor|default|strict] [--upstream-echo] [--api-key KEY | --api-key-env]",
  );
  process.exit(1);
}

function main(): void {
  const args = process.argv.slice(2);
  let port = 3000;
  let policy = DEFAULT_POLICY;
  let upstream: ((prompt: string) => string) | undefined;
  let apiKey: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--port") port = Number(args[++i]);
    else if (arg === "--policy") {
      const named = POLICIES[args[++i]!];
      if (!named) usage();
      policy = named;
    } else if (arg === "--upstream-echo") {
      upstream = (prompt: string) => `Echo: ${prompt}`;
    } else if (arg === "--api-key") apiKey = args[++i];
    else if (arg === "--api-key-env") apiKey = process.env.PF_API_KEY;
    else usage();
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65535) usage();
  if (args.includes("--api-key-env") && !apiKey) {
    console.error("PF_API_KEY is not set");
    process.exit(1);
  }

  const { server } = createProxyServer({ policy, upstream, apiKey });
  server.listen(port, () => {
    console.log(`prompt-firewall proxy listening on http://localhost:${port} (policy: ${policy.name})`);
  });
}

main();
