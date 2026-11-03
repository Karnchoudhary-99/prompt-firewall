#!/usr/bin/env node
/**
 * Minimal CLI for the prompt scanner.
 *
 *   npm run scan -- "Ignore all previous instructions"
 *   npm run scan -- --json "You are now a pirate"
 *   echo "Write a haiku" | npm run scan
 *
 * Exit code: 0 = allow, 2 = flag, 3 = block, 1 = usage error.
 */
import { readFileSync } from "node:fs";
import { scanPrompt } from "./scanner.js";

function usage(): never {
  console.error(
    "Usage: pf-scan [--json] [--block-at N] [--flag-at N] <prompt | - | @file>",
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
  let blockAt: number | undefined;
  let flagAt: number | undefined;
  let input: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--json") json = true;
    else if (arg === "--block-at") blockAt = Number(args[++i]);
    else if (arg === "--flag-at") flagAt = Number(args[++i]);
    else if (input === undefined) input = arg;
    else usage();
  }
  if (input === undefined) usage();

  const text =
    input === "-"
      ? await readStdin()
      : input.startsWith("@")
        ? readFileSync(input.slice(1), "utf8")
        : input;

  const result = scanPrompt(text.trim(), {
    ...(blockAt !== undefined ? { blockThreshold: blockAt } : {}),
    ...(flagAt !== undefined ? { flagThreshold: flagAt } : {}),
  });

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`verdict: ${result.verdict}  score: ${result.score}/100`);
    if (result.findings.length === 0) {
      console.log("no findings — prompt is clean");
    } else {
      for (const f of result.findings) {
        console.log(`- [${f.severity}] ${f.ruleId}: ${f.message}`);
        console.log(`    match: ${JSON.stringify(f.match)} (offset ${f.index})`);
      }
    }
  }
  process.exit(result.verdict === "block" ? 3 : result.verdict === "flag" ? 2 : 0);
}

await main();
