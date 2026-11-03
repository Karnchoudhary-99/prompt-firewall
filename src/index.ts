export const VERSION = "0.1.0";

export { scanPrompt, shouldBlock } from "./scanner.js";
export { RULES, runRule, truncateMatch, type Rule } from "./rules.js";
export {
  SEVERITY_WEIGHTS,
  compareSeverity,
  type Finding,
  type FindingCategory,
  type ScanResult,
  type ScannerOptions,
  type Severity,
  type Verdict,
} from "./types.js";
