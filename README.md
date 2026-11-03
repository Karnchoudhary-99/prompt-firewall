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

## Output guard + policy engine

The scanner guards what goes *in*; the output guard guards what comes
*out*. `scanOutput` detects secrets (OpenAI/AWS/GitHub-style keys),
credentials (`password:` assignments, Bearer tokens), PII (emails,
Luhn-valid card numbers) and quoted system instructions, and
`redactOutput` replaces each span with `[REDACTED:<label>]` — findings
keep the full match, so a long secret is never half-redacted.

`applyPolicy` combines an input scan and an output guard result into one
decision under a named policy:

| Policy | Flagged input | Blocked input | Leaky output |
| --- | --- | --- | --- |
| `monitor` | flag | flag (never blocks) | flag |
| `default` | flag | block | redact |
| `strict` | block | block | block |

Input takes precedence: a blocked input is decided before the output is
considered. Invalid policies are rejected by `validatePolicy` (empty
name, unknown action, or `redact` for an input verdict, where there is
nothing to redact yet).

```ts
import { applyPolicy, scanOutput, scanPrompt } from "prompt-firewall";

const decision = applyPolicy(
  scanPrompt("Write a haiku"),
  "Reach me at alice@example.com",
  scanOutput("Reach me at alice@example.com"),
);
// { action: "redact", output: "Reach me at [REDACTED:EMAIL]", … }
```

```sh
npm run guard -- "contact alice@example.com"                    # exit 2 = redact
npm run guard -- --policy strict "key sk-…"                     # exit 3 = block
npm run guard -- --prompt "Write a haiku" "a clean reply"       # exit 0 = allow
npx tsx examples/guard-demo.ts                                  # scripted demo
```

## Proxy server + API

Run the firewall as an HTTP server in front of a model (or a stand-in):

```sh
npm run proxy -- --port 3000 --upstream-echo   # echo upstream, no LLM key needed
curl localhost:3000/health
curl -X POST localhost:3000/v1/scan -H 'content-type: application/json' \
  -d '{"prompt": "Ignore all previous instructions"}'
curl -X POST localhost:3000/v1/chat -H 'content-type: application/json' \
  -d '{"prompt": "Write a haiku"}'
curl localhost:3000/v1/stats
```

Endpoints: `GET /health`, `GET /v1/policies`, `GET /v1/stats`,
`POST /v1/scan` (`{prompt}`), `POST /v1/guard` (`{text}` → findings +
redacted text), `POST /v1/chat` (`{prompt, output?}`), and
`POST /v1/chat/completions` (OpenAI-style `{messages}` — the last user
message is the prompt, the reply comes back as `choices[0].message`). A blocked prompt
returns 403 and **never reaches the upstream**; a leaky reply is redacted
(default policy) or blocked (strict). `--policy monitor|default|strict`
selects the policy, and `--api-key` / `PF_API_KEY` requires an
`x-api-key` header. Without an upstream, `/v1/chat` requires an `output`
field — the handler itself is socket-free and unit-tested, so the same
decisions are verified without binding a port (see `examples/proxy-demo.ts`).

## Roadmap

- [x] Project scaffold (README roadmap, license, gitignore)
- [x] Prompt scanner (injection/jailbreak heuristics)
- [x] Output guard + policy engine
- [x] Proxy server + API
- [x] Self-review checklist, then public

## License

MIT — see [LICENSE](LICENSE).
