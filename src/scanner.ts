import { RULES, runRule } from "./rules.js";
import {
  SEVERITY_WEIGHTS,
  compareSeverity,
  type Finding,
  type ScanResult,
  type ScannerOptions,
  type Severity,
  type Verdict,
} from "./types.js";

const DEFAULTS = {
  blockThreshold: 70,
  flagThreshold: 30,
  maxFindings: 25,
} as const;

/**
 * Scan a prompt for injection / jailbreak / exfiltration attempts.
 *
 * The scan is deterministic and offline: every rule is a fixed pattern, so
 * the same input always yields the same result — no LLM call, no network.
 * Empty and whitespace-only prompts scan clean.
 */
export function scanPrompt(text: string, options: ScannerOptions = {}): ScanResult {
  const blockThreshold = options.blockThreshold ?? DEFAULTS.blockThreshold;
  const flagThreshold = options.flagThreshold ?? DEFAULTS.flagThreshold;
  const maxFindings = options.maxFindings ?? DEFAULTS.maxFindings;
  const disabled = new Set(options.disabledRules ?? []);

  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (disabled.has(rule.id)) continue;
    const finding = runRule(rule, text);
    if (finding) findings.push(finding);
  }

  // Highest severity first, then earliest in the text, for stable reports.
  findings.sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.index - b.index,
  );
  const kept = findings.slice(0, maxFindings);

  const score = Math.min(
    100,
    kept.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0),
  );
  const maxSeverity: Severity | null =
    kept.length > 0 ? kept[0]!.severity : null;

  const verdict: Verdict =
    score >= blockThreshold ? "block" : score >= flagThreshold ? "flag" : "allow";

  return { verdict, score, findings: kept, maxSeverity };
}

/** Convenience: true when the prompt should not reach the model. */
export function shouldBlock(text: string, options?: ScannerOptions): boolean {
  return scanPrompt(text, options).verdict === "block";
}
