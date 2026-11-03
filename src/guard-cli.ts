#!/usr/bin/env node
/**
 * CLI for the output guard + policy engine.
 *
 *   npm run guard -- "contact alice@example.com"            # redacted output
 *   npm run guard -- --policy strict "key sk-…"
 *   npm run guard -- --json --prompt "Write a haiku" "a reply"
 *
 * Without --prompt only the output is guarded. With --prompt the input is
 * scanned first and the policy decides the whole request.
 *
 * Exit code: 0 = allow, 2 = flag/redact, 3 = block, 1 = usage error.
 */
import { readFileSync } from "node:fs";
import { scanOutput } from "./output.js";
import {
  DEFAULT_POLICY,
  MONITOR_POLICY,
  STRICT_POLICY,
  applyPolicy,
  type Policy,
} from "./policy.js";
import { scanPrompt } from "./scanner.js";

const POLICIES: Record<string, Policy> = {
  monitor: MONITOR_POLICY,
  default: DEFAULT_POLICY,
  strict: STRICT_POLICY,
};

function usage(): never {
  console.error(
    "Usage: pf-guard [--json] [--policy monitor|default|strict] [--prompt <input>] <output | - | @file>",
  );
  process.exit(1);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let json = false;
  let policyName = "default";
  let prompt: string | undefined;
  let input: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--json") json = true;
    else if (arg === "--policy") policyName = args[++i] ?? usage();
    else if (arg === "--prompt") prompt = args[++i] ?? usage();
    else if (input === undefined) input = arg;
    else usage();
  }
  if (input === undefined) usage();
  const policy = POLICIES[policyName];
  if (!policy) {
    console.error(`unknown policy: ${policyName}`);
    process.exit(1);
  }

  const outputText =
    input === "-"
      ? await readStdin()
      : input.startsWith("@")
        ? readFileSync(input.slice(1), "utf8")
        : input;

  const inputScan = prompt !== undefined ? scanPrompt(prompt) : undefined;
  const guard = scanOutput(outputText);
  const decision = applyPolicy(inputScan, outputText, guard, policy);

  if (json) {
    console.log(
      JSON.stringify(
        { policy: policy.name, decision, inputScan, guard },
        null,
        2,
      ),
    );
  } else {
    console.log(`policy: ${policy.name}  action: ${decision.action}`);
    console.log(`reason: ${decision.reason}`);
    if (guard.findings.length > 0) {
      for (const f of guard.findings) {
        console.log(`- [${f.category}] ${f.ruleId}: ${f.message}`);
      }
    }
    if (decision.output !== undefined) {
      console.log("output:");
      console.log(decision.output);
    }
  }
  process.exit(
    decision.action === "block"
      ? 3
      : decision.action === "flag" || decision.action === "redact"
        ? 2
        : 0,
  );
}

await main();
