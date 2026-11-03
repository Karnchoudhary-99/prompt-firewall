import type { Finding, FindingCategory, Severity } from "./types.js";

/**
 * One detection rule: a regex (or a custom check) plus its metadata.
 * Regexes run case-insensitively against the raw prompt text; the match
 * and its offset are reported so callers can highlight or redact it.
 */
export interface Rule {
  id: string;
  category: FindingCategory;
  severity: Severity;
  message: string;
  pattern?: RegExp;
  /** Custom check for patterns a single regex cannot express well. */
  check?: (text: string) => { match: string; index: number } | null;
}

function regexRule(
  id: string,
  category: FindingCategory,
  severity: Severity,
  message: string,
  source: string,
): Rule {
  return { id, category, severity, message, pattern: new RegExp(source, "i") };
}

function checkRule(
  id: string,
  category: FindingCategory,
  severity: Severity,
  message: string,
  check: Rule["check"],
): Rule {
  return { id, category, severity, message, check };
}

/** Truncate long matches for readable reports (keep head + tail). */
export function truncateMatch(match: string, limit = 120): string {
  if (match.length <= limit) return match;
  return `${match.slice(0, 60)}…${match.slice(-59)}`;
}

export const RULES: Rule[] = [
  // ---- instruction override: tries to cancel or replace prior instructions ----
  regexRule(
    "instruction-override.ignore-previous",
    "instruction-override",
    "critical",
    "Attempts to cancel prior instructions ('ignore previous instructions').",
    "\\bignore\\s+(all\\s+)?(previous|prior|earlier|above)\\s+instructions\\b",
  ),
  regexRule(
    "instruction-override.disregard",
    "instruction-override",
    "high",
    "Attempts to disregard the instructions the model was given.",
    "\\b(disregard|forget|override|discard)\\s+(your|the|all)\\s+(previous\\s+|prior\\s+)?instructions?\\b",
  ),
  regexRule(
    "instruction-override.new-instructions",
    "instruction-override",
    "high",
    "Declares a new instruction set that supersedes the original one.",
    "\\b(new|updated|revised)\\s+instructions?\\s+(are|follow|from now on)\\b",
  ),
  regexRule(
    "instruction-override.do-not-follow",
    "instruction-override",
    "medium",
    "Tells the model not to follow its safety or system rules.",
    "\\bdo\\s+not\\s+follow\\s+(your\\s+)?(rules?|guidelines?|policy|restrictions?)\\b",
  ),

  // ---- role hijack: redefines who the model is or what role it plays ----
  regexRule(
    "role-hijack.you-are-now",
    "role-hijack",
    "high",
    "Reassigns the model's identity ('you are now …').",
    "\\byou\\s+are\\s+now\\s+(a|an|the)?\\s*\\w+",
  ),
  regexRule(
    "role-hijack.pretend",
    "role-hijack",
    "medium",
    "Asks the model to pretend to be something else.",
    "\\bpretend\\s+(you\\s+are|to\\s+be)\\b",
  ),
  regexRule(
    "role-hijack.act-as",
    "role-hijack",
    "medium",
    "Asks the model to act as an unrestricted persona.",
    "\\bact\\s+as\\s+(an?\\s+)?(unrestricted|uncensored|unfiltered|evil|jailbroken)\\b",
  ),
  regexRule(
    "role-hijack.new-persona",
    "role-hijack",
    "high",
    "Installs a new persona that replaces the assistant's identity.",
    "\\bfrom\\s+now\\s+on\\s*,?\\s*you\\s+(are|will\\s+be)\\b",
  ),

  // ---- known jailbreak shorthands ----
  regexRule(
    "jailbreak.dan",
    "jailbreak",
    "critical",
    "References the DAN ('Do Anything Now') jailbreak persona.",
    "\\bDAN\\b.{0,40}\\b(do\\s+anything\\s+now|mode)\\b|\\bdo\\s+anything\\s+now\\b",
  ),
  regexRule(
    "jailbreak.developer-mode",
    "jailbreak",
    "high",
    "Requests a 'developer mode' that bypasses restrictions.",
    "\\bdeveloper\\s+mode\\b",
  ),
  regexRule(
    "jailbreak.jailbreak-word",
    "jailbreak",
    "high",
    "Explicitly asks to jailbreak or break out of restrictions.",
    "\\bjailbreak\\b|\\bbreak\\s+out\\s+of\\s+your\\s+(restrictions|rules|guidelines)\\b",
  ),
  regexRule(
    "jailbreak.no-restrictions",
    "jailbreak",
    "medium",
    "Asks the model to answer without its usual restrictions.",
    "\\bwithout\\s+(any\\s+)?(restrictions?|limits?|filters?|censorship)\\b",
  ),

  // ---- system-prompt leak: tries to extract the hidden instructions ----
  regexRule(
    "system-prompt-leak.reveal",
    "system-prompt-leak",
    "critical",
    "Asks the model to reveal its system prompt or hidden instructions.",
    "\\b(reveal|show|print|output|repeat)\\s+(your\\s+)?(system\\s+prompt|hidden\\s+instructions?|initial\\s+instructions?)\\b",
  ),
  regexRule(
    "system-prompt-leak.what-are-instructions",
    "system-prompt-leak",
    "high",
    "Asks what instructions the model was given.",
    "\\bwhat\\s+(instructions?|prompt)\\s+(were\\s+you\\s+given|are\\s+you\\s+following)\\b",
  ),
  regexRule(
    "system-prompt-leak.verbatim",
    "system-prompt-leak",
    "high",
    "Asks for a verbatim repeat of the system prompt.",
    "\\brepeat\\s+verbatim\\b.{0,40}\\b(system|instructions?)\\b|\\bverbatim\\s+(system|prompt)\\b",
  ),

  // ---- delimiter injection: fakes a system/developer turn inside user text ----
  regexRule(
    "delimiter-injection.chatml-tag",
    "delimiter-injection",
    "critical",
    "Embeds a fake chat turn tag (<|system|>, [SYSTEM], etc.) in user text.",
    "<\\|\\s*(system|developer|assistant)\\s*\\|>|\\[\\s*SYSTEM\\s*\\]|\\bSYSTEM\\s*:",
  ),
  regexRule(
    "delimiter-injection.instruction-block",
    "delimiter-injection",
    "high",
    "Wraps injected instructions in a fake instruction block.",
    "###\\s*Instruction\\b|<\\s*instructions?\\s*>",
  ),

  // ---- encoded payload: smuggles instructions past keyword filters ----
  checkRule(
    "encoded-payload.zero-width",
    "encoded-payload",
    "high",
    "Contains zero-width / invisible characters often used to smuggle text.",
    (text) => {
      const m = /[\u200B-\u200F\uFEFF]/.exec(text);
      return m ? { match: "invisible character U+" + m[0].codePointAt(0)!.toString(16).toUpperCase(), index: m.index } : null;
    },
  ),
  checkRule(
    "encoded-payload.long-base64",
    "encoded-payload",
    "medium",
    "Contains a long base64-looking blob that may hide an instruction.",
    (text) => {
      const m = /\b[A-Za-z0-9+/]{80,}={0,2}\b/.exec(text);
      return m ? { match: truncateMatch(m[0]), index: m.index } : null;
    },
  ),
  checkRule(
    "encoded-payload.decode-then-follow",
    "encoded-payload",
    "high",
    "Asks the model to decode a payload and then follow it.",
    (text) => {
      const m = /\b(decode|decrypt|unscramble)\b.{0,60}\b(then|and)\b.{0,40}\b(follow|execute|do what it says)\b/i.exec(text);
      return m ? { match: truncateMatch(m[0]), index: m.index } : null;
    },
  ),

  // ---- exfiltration: tries to make the model leak secrets or send data out ----
  regexRule(
    "exfiltration.reveal-secrets",
    "exfiltration",
    "critical",
    "Asks the model to reveal secrets, keys, or passwords.",
    "\\b(reveal|show|give|print|leak)\\b.{0,40}\\b(api\\s+keys?|passwords?|secrets?|credentials?|private\\s+keys?)\\b",
  ),
  regexRule(
    "exfiltration.send-to-url",
    "exfiltration",
    "high",
    "Asks the model to send data to an external URL.",
    "\\b(send|post|upload|exfiltrate)\\b.{0,50}\\bhttps?://\\S+",
  ),
];

export function runRule(rule: Rule, text: string): Finding | null {
  if (rule.check) {
    const hit = rule.check(text);
    if (!hit) return null;
    return {
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      message: rule.message,
      match: hit.match,
      index: hit.index,
    };
  }
  if (!rule.pattern) return null;
  // Fresh regex per run: patterns are stored without the global flag, but
  // never rely on lastIndex state across calls.
  const re = new RegExp(rule.pattern.source, rule.pattern.flags);
  const m = re.exec(text);
  if (!m) return null;
  return {
    ruleId: rule.id,
    category: rule.category,
    severity: rule.severity,
    message: rule.message,
    match: truncateMatch(m[0]),
    index: m.index,
  };
}
