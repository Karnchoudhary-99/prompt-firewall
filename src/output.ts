/**
 * Output guard: scan a model's reply before it reaches the user.
 *
 * Mirrors the prompt scanner's deterministic, offline style: fixed regexes
 * plus a Luhn check for card numbers, so the same output always yields the
 * same verdict. It looks for the things a model must never leak — secrets,
 * credentials, PII and quoted system instructions — and can redact them
 * instead of blocking the whole reply.
 */

export type OutputCategory =
  | "secret"
  | "credential"
  | "pii"
  | "system-prompt-leak";

export interface OutputFinding {
  /** Stable rule id, e.g. "secret.openai-key". */
  ruleId: string;
  category: OutputCategory;
  /** Human-readable explanation of why this matched. */
  message: string;
  /** The matched substring, truncated for long inputs. */
  match: string;
  /** Character offset of the match, or -1 if synthetic. */
  index: number;
  /** Replacement used by redactOutput, e.g. "[REDACTED:API_KEY]". */
  redactionLabel: string;
}

export interface GuardResult {
  /** True when at least one output rule matched. */
  blocked: boolean;
  findings: OutputFinding[];
}

export interface GuardOptions {
  /** Rule ids to skip. */
  disabledRules?: string[];
  /** Maximum findings returned, earliest first (default 25). */
  maxFindings?: number;
}

interface OutputRule {
  id: string;
  category: OutputCategory;
  message: string;
  redactionLabel: string;
  pattern: RegExp;
  /** Extra validation a match must pass (e.g. Luhn for card numbers). */
  validate?: (match: string) => boolean;
}

function rule(
  id: string,
  category: OutputCategory,
  message: string,
  redactionLabel: string,
  source: string,
  flags = "gi",
  validate?: (match: string) => boolean,
): OutputRule {
  return {
    id,
    category,
    message,
    redactionLabel,
    pattern: new RegExp(source, flags),
    validate,
  };
}

/** Luhn checksum: true for plausible 13–19 digit card numbers. */
export function passesLuhn(digits: string): boolean {
  const clean = digits.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(clean)) return false;
  let sum = 0;
  let doubleNext = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = Number(clean[i]);
    if (doubleNext) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleNext = !doubleNext;
  }
  return sum % 10 === 0;
}

const RULES: OutputRule[] = [
  rule(
    "secret.openai-key",
    "secret",
    "Looks like an OpenAI API key (sk-… / sk-proj-…).",
    "API_KEY",
    "\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\\b",
  ),
  rule(
    "secret.aws-access-key",
    "secret",
    "Looks like an AWS access key id (AKIA…).",
    "AWS_KEY",
    "\\bAKIA[0-9A-Z]{16}\\b",
  ),
  rule(
    "secret.github-token",
    "secret",
    "Looks like a GitHub personal access token (ghp_… / github_pat_…).",
    "GITHUB_TOKEN",
    "\\b(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\\b",
  ),
  rule(
    "credential.password-assignment",
    "credential",
    "Assigns a password value in the output.",
    "PASSWORD",
    "\\bpassword\\s*[:=]\\s*\\S+",
    "gi",
  ),
  rule(
    "credential.bearer-token",
    "credential",
    "Carries a Bearer token.",
    "BEARER_TOKEN",
    "\\bBearer\\s+[A-Za-z0-9._-]{20,}\\b",
  ),
  rule(
    "pii.email",
    "pii",
    "Contains an email address.",
    "EMAIL",
    "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
  ),
  rule(
    "pii.card-number",
    "pii",
    "Contains a number that passes the Luhn card-number check.",
    "CARD_NUMBER",
    "\\b\\d[\\d\\s-]{12,18}\\d\\b",
    "g",
    passesLuhn,
  ),
  rule(
    "system-prompt-leak.quoted-instructions",
    "system-prompt-leak",
    "Quotes the model's own system instructions back to the user.",
    "SYSTEM_PROMPT",
    "\\bmy\\s+(system\\s+prompt|instructions)\\s+(are|say|is)\\b.{0,80}",
    "gi",
  ),
];

/**
 * Output findings keep the FULL match (unlike prompt-scanner findings):
 * redactOutput slices by match length, so a truncated match would leave
 * part of a secret behind. Callers printing findings should truncate
 * for display themselves.
 */

/**
 * Scan model output for secrets, credentials, PII and system-prompt leaks.
 * Empty and whitespace-only outputs scan clean.
 */
export function scanOutput(text: string, options: GuardOptions = {}): GuardResult {
  const disabled = new Set(options.disabledRules ?? []);
  const maxFindings = options.maxFindings ?? 25;
  const findings: OutputFinding[] = [];

  for (const r of RULES) {
    if (disabled.has(r.id)) continue;
    // Fresh RegExp per rule is already the case (module-level, but reset
    // lastIndex before each global scan so repeated calls stay stable).
    r.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = r.pattern.exec(text)) !== null) {
      const match = m[0];
      if (r.validate && !r.validate(match)) continue;
      findings.push({
        ruleId: r.id,
        category: r.category,
        message: r.message,
        match,
        index: m.index,
        redactionLabel: r.redactionLabel,
      });
      if (!r.pattern.global) break;
    }
  }

  findings.sort((a, b) => a.index - b.index);
  const kept = findings.slice(0, maxFindings);
  return { blocked: kept.length > 0, findings: kept };
}

export interface RedactionResult {
  /** The output with every finding replaced by its [REDACTED:…] label. */
  text: string;
  /** How many spans were replaced. */
  redactions: number;
  findings: OutputFinding[];
}

/**
 * Redact every finding in `text`, replacing each matched span with
 * `[REDACTED:<label>]`. Spans are applied right-to-left so earlier offsets
 * stay valid. Overlapping findings keep only the earliest span.
 */
export function redactOutput(text: string, result?: GuardResult): RedactionResult {
  const guard = result ?? scanOutput(text);
  let out = text;
  let redactions = 0;
  // Accept spans left-to-right, skipping any that overlap an accepted span,
  // then apply them right-to-left so earlier offsets stay valid.
  const accepted: OutputFinding[] = [];
  for (const f of [...guard.findings].sort((a, b) => a.index - b.index)) {
    const prev = accepted[accepted.length - 1];
    if (prev && f.index < prev.index + prev.match.length) continue;
    accepted.push(f);
  }
  for (const f of [...accepted].sort((a, b) => b.index - a.index)) {
    out =
      out.slice(0, f.index) +
      `[REDACTED:${f.redactionLabel}]` +
      out.slice(f.index + f.match.length);
    redactions++;
  }
  return { text: out, redactions, findings: guard.findings };
}
