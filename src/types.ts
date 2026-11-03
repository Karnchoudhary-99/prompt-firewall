/** Shared types for the prompt scanner. */

export type Severity = "low" | "medium" | "high" | "critical";

/** What kind of attack a finding describes. */
export type FindingCategory =
  | "instruction-override"
  | "role-hijack"
  | "jailbreak"
  | "system-prompt-leak"
  | "delimiter-injection"
  | "encoded-payload"
  | "exfiltration";

export interface Finding {
  /** Stable rule id, e.g. "instruction-override.ignore-previous". */
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  /** Human-readable explanation of why this matched. */
  message: string;
  /** The exact substring that triggered the rule (truncated for long inputs). */
  match: string;
  /** Character offset of the match within the scanned text, or -1 if synthetic. */
  index: number;
}

export type Verdict = "allow" | "flag" | "block";

export interface ScanResult {
  verdict: Verdict;
  /** 0 (clean) to 100 (certain attack). Sum of finding weights, capped at 100. */
  score: number;
  findings: Finding[];
  /** The highest severity among the findings, or null for a clean scan. */
  maxSeverity: Severity | null;
}

export interface ScannerOptions {
  /** Score at or above which the verdict becomes "block" (default 70). */
  blockThreshold?: number;
  /** Score at or above which the verdict becomes "flag" (default 25). */
  flagThreshold?: number;
  /** Rule ids to skip, e.g. to allow a known-benign pattern in a trusted app. */
  disabledRules?: string[];
  /** Maximum findings returned, highest severity first (default 25). */
  maxFindings?: number;
}

/** Weight each severity contributes to the 0-100 score. */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  low: 10,
  medium: 25,
  high: 45,
  critical: 70,
};

const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}
