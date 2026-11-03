/**
 * Policy engine: turns an input scan and an output guard result into one
 * final action for a request, under a named policy.
 *
 * Policies are plain data so an app can ship one per environment:
 * MONITOR logs everything and never blocks, DEFAULT blocks hostile inputs
 * and redacts leaky outputs, STRICT blocks anything flagged on either side.
 * Invalid policies are rejected up front (validatePolicy) rather than
 * silently misbehaving at request time.
 */
import { redactOutput, type GuardResult } from "./output.js";
import type { ScanResult, Verdict } from "./types.js";

export type PolicyAction = "allow" | "flag" | "block" | "redact";

export interface Policy {
  /** Human-readable name, e.g. "default". */
  name: string;
  /**
   * How to treat a flagged (but not blocked) input scan. Defaults to
   * "flag" — the request proceeds, but the flag is reported.
   */
  onFlaggedInput?: PolicyAction;
  /**
   * How to treat a blocked input scan. Defaults to "block".
   */
  onBlockedInput?: PolicyAction;
  /**
   * How to treat output that triggered the guard. Defaults to "redact":
   * the reply proceeds with secrets/PII replaced, which is safer than
   * dropping a mostly-clean answer and more useful than passing a leak.
   */
  onLeakyOutput?: PolicyAction;
}

export const MONITOR_POLICY: Policy = {
  name: "monitor",
  onFlaggedInput: "flag",
  onBlockedInput: "flag",
  onLeakyOutput: "flag",
};

export const DEFAULT_POLICY: Policy = {
  name: "default",
  onFlaggedInput: "flag",
  onBlockedInput: "block",
  onLeakyOutput: "redact",
};

export const STRICT_POLICY: Policy = {
  name: "strict",
  onFlaggedInput: "block",
  onBlockedInput: "block",
  onLeakyOutput: "block",
};

/** Resolve an action field, falling back to the documented default. */
function resolve(
  value: PolicyAction | undefined,
  fallback: PolicyAction,
): PolicyAction {
  return value ?? fallback;
}

/**
 * Throw on a policy that cannot be honoured: an empty name, an unknown
 * action, or a redact action for an input verdict (there is nothing to
 * redact in a prompt that has not been answered yet — use flag/block).
 */
export function validatePolicy(policy: Policy): void {
  if (!policy.name.trim()) throw new Error("policy name must not be empty");
  const actions: PolicyAction[] = ["allow", "flag", "block", "redact"];
  for (const [field, value] of [
    ["onFlaggedInput", policy.onFlaggedInput],
    ["onBlockedInput", policy.onBlockedInput],
    ["onLeakyOutput", policy.onLeakyOutput],
  ] as const) {
    if (value !== undefined && !actions.includes(value)) {
      throw new Error(`policy.${field} is not a known action: ${value}`);
    }
  }
  if (policy.onFlaggedInput === "redact" || policy.onBlockedInput === "redact") {
    throw new Error("policy input actions cannot be 'redact'");
  }
}

export interface PolicyDecision {
  action: PolicyAction;
  /** Why this action was chosen, for logs and audit trails. */
  reason: string;
  /** The output after redaction, when action is "redact"; otherwise as given. */
  output: string | undefined;
  /** Input verdict that drove the decision, when an input scan was given. */
  inputVerdict: Verdict | undefined;
  /** Whether the output guard fired. */
  outputBlocked: boolean;
}

/**
 * Decide one request. Input takes precedence: a blocked input is decided
 * before the output is even considered (the model should never have been
 * called). A leaky output under a redact policy returns the redacted text.
 */
export function applyPolicy(
  input: ScanResult | undefined,
  outputText: string | undefined,
  outputGuard: GuardResult | undefined,
  policy: Policy = DEFAULT_POLICY,
): PolicyDecision {
  validatePolicy(policy);

  if (input?.verdict === "block") {
    return {
      action: resolve(policy.onBlockedInput, "block"),
      reason: `input scan blocked (score ${input.score})`,
      output: undefined,
      inputVerdict: input.verdict,
      outputBlocked: outputGuard?.blocked ?? false,
    };
  }
  if (input?.verdict === "flag") {
    const action = resolve(policy.onFlaggedInput, "flag");
    // A flagged input still proceeds unless the policy blocks it; if the
    // output also leaks, the output action wins only when it is stricter
    // (block > redact > flag), because a leak must not ride out on a flag.
    if (action === "block") {
      return {
        action,
        reason: `input scan flagged (score ${input.score}) and policy blocks flagged inputs`,
        output: undefined,
        inputVerdict: input.verdict,
        outputBlocked: outputGuard?.blocked ?? false,
      };
    }
    if (outputGuard?.blocked && outputText !== undefined) {
      const outAction = resolve(policy.onLeakyOutput, "redact");
      if (outAction === "block") {
        return {
          action: "block",
          reason: `output guard fired (${outputGuard.findings.length} finding(s))`,
          output: undefined,
          inputVerdict: input.verdict,
          outputBlocked: true,
        };
      }
      if (outAction === "redact") {
        return {
          action: "redact",
          reason: `input flagged (score ${input.score}); output guard fired, redacted`,
          output: redactOutput(outputText, outputGuard).text,
          inputVerdict: input.verdict,
          outputBlocked: true,
        };
      }
    }
    return {
      action,
      reason: `input scan flagged (score ${input.score})`,
      output: outputText,
      inputVerdict: input.verdict,
      outputBlocked: outputGuard?.blocked ?? false,
    };
  }

  if (outputGuard?.blocked && outputText !== undefined) {
    const outAction = resolve(policy.onLeakyOutput, "redact");
    if (outAction === "block") {
      return {
        action: "block",
        reason: `output guard fired (${outputGuard.findings.length} finding(s))`,
        output: undefined,
        inputVerdict: input?.verdict,
        outputBlocked: true,
      };
    }
    if (outAction === "redact") {
      return {
        action: "redact",
        reason: `output guard fired (${outputGuard.findings.length} finding(s)), redacted`,
        output: redactOutput(outputText, outputGuard).text,
        inputVerdict: input?.verdict,
        outputBlocked: true,
      };
    }
    return {
      action: outAction,
      reason: `output guard fired (${outputGuard.findings.length} finding(s))`,
      output: outputText,
      inputVerdict: input?.verdict,
      outputBlocked: true,
    };
  }

  return {
    action: "allow",
    reason: "input and output scans clean",
    output: outputText,
    inputVerdict: input?.verdict,
    outputBlocked: false,
  };
}
