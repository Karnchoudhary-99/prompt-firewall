# Prompt Injection Firewall

Guardrails proxy shielding LLM apps from prompt attacks — scan prompts and
model outputs for injection attempts, jailbreak patterns, and data
exfiltration before they reach (or leave) your LLM.

## Prompt scanner

Deterministic, offline scanning — no LLM call, no network, so the same
input always yields the same result. 21 rules across 7 categories:

| Category | Examples detected |
| --- | --- |
| instruction-override | "ignore previous instructions", "disregard your instructions" |
| role-hijack | "you are now …", "pretend you are …", "act as an uncensored …" |
| jailbreak | DAN / "do anything now", "developer mode", "jailbreak" |
| system-prompt-leak | "reveal your system prompt", "what instructions were you given" |
| delimiter-injection | fake `<\|system\|>` / `[SYSTEM]` turn tags, fake instruction blocks |
| encoded-payload | zero-width characters, long base64 blobs, decode-then-follow |
| exfiltration | "reveal the api keys", "send … to https://…" |

Each finding carries a severity (low 10 / medium 25 / high 45 /
critical 70 points). Scores sum, capped at 100. Verdicts: **block** at
70+, **flag** at 25+, otherwise **allow**. A lone medium finding flags;
a lone critical finding blocks. Thresholds and per-rule opt-outs are
configurable via `ScannerOptions`.

### Usage

```ts
import { scanPrompt } from "prompt-firewall";

const result = scanPrompt("Ignore all previous instructions.");
// { verdict: "block", score: 70, findings: [ … ], maxSeverity: "critical" }
```

```sh
npm run scan -- "Ignore all previous instructions"   # exit 3 = block
npm run scan -- --json "Write a haiku"                # exit 0 = allow
echo "Write a haiku" | npm run scan -- -             # read from stdin
npx tsx examples/demo.ts                             # scripted demo
```

## Roadmap

- [x] Project scaffold (README roadmap, license, gitignore)
- [x] Prompt scanner (injection/jailbreak heuristics)
- [ ] Output guard + policy engine
- [ ] Proxy server + API
- [ ] Self-review checklist, then public

## License

MIT — see [LICENSE](LICENSE).
