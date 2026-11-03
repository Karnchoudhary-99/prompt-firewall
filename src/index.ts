export const VERSION = "0.1.0";

export { scanPrompt, shouldBlock } from "./scanner.js";
export {
  passesLuhn,
  redactOutput,
  scanOutput,
  type GuardOptions,
  type GuardResult,
  type OutputCategory,
  type OutputFinding,
  type RedactionResult,
} from "./output.js";
export {
  DEFAULT_POLICY,
  MONITOR_POLICY,
  STRICT_POLICY,
  applyPolicy,
  validatePolicy,
  type Policy,
  type PolicyAction,
  type PolicyDecision,
} from "./policy.js";
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
export {
  POLICIES,
  createProxyHandler,
  type ProxyOptions,
  type ProxyRequest,
  type ProxyResponse,
  type ProxyStats,
} from "./proxy.js";
export { createProxyServer } from "./server.js";
