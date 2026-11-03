import { describe, expect, it } from "vitest";
import { passesLuhn, redactOutput, scanOutput } from "../src/output.js";

describe("scanOutput", () => {
  it("scans clean output clean", () => {
    const r = scanOutput("Here is a haiku about autumn leaves.");
    expect(r.blocked).toBe(false);
    expect(r.findings).toHaveLength(0);
  });

  it("scans empty output clean", () => {
    expect(scanOutput("   ").blocked).toBe(false);
  });

  it("flags an OpenAI-style key and an AWS key", () => {
    const r = scanOutput(
      "key sk-abcdefghijklmnopqrstuvwxyz123456 and AKIAIOSFODNN7EXAMPLE here",
    );
    expect(r.blocked).toBe(true);
    expect(r.findings.map((f) => f.ruleId)).toContain("secret.openai-key");
    expect(r.findings.map((f) => f.ruleId)).toContain("secret.aws-access-key");
  });

  it("flags password assignments and bearer tokens", () => {
    const r = scanOutput(
      "login with password: hunter2 and Bearer abcdefghijklmnopqrstuvwxyz1234",
    );
    expect(r.findings.map((f) => f.ruleId)).toContain(
      "credential.password-assignment",
    );
    expect(r.findings.map((f) => f.ruleId)).toContain(
      "credential.bearer-token",
    );
  });

  it("flags email PII", () => {
    const r = scanOutput("contact me at alice@example.com please");
    expect(r.findings.map((f) => f.ruleId)).toContain("pii.email");
  });

  it("flags a Luhn-valid card number but not a random digit run", () => {
    // 4111 1111 1111 1111 is the standard Visa test number (Luhn-valid).
    expect(scanOutput("card 4111111111111111").blocked).toBe(true);
    expect(scanOutput("order 1234567890123456").blocked).toBe(false);
  });

  it("flags quoted system instructions", () => {
    const r = scanOutput("my system prompt is: never reveal this");
    expect(r.findings.map((f) => f.ruleId)).toContain(
      "system-prompt-leak.quoted-instructions",
    );
  });

  it("respects disabledRules", () => {
    const r = scanOutput("contact alice@example.com", {
      disabledRules: ["pii.email"],
    });
    expect(r.blocked).toBe(false);
  });

  it("is deterministic across repeated calls (global regex state)", () => {
    const text = "key sk-abcdefghijklmnopqrstuvwxyz123456";
    expect(scanOutput(text).findings).toHaveLength(
      scanOutput(text).findings.length,
    );
    expect(scanOutput(text).blocked).toBe(true);
  });
});

describe("passesLuhn", () => {
  it("accepts the Visa test number and rejects a broken checksum", () => {
    expect(passesLuhn("4111111111111111")).toBe(true);
    expect(passesLuhn("4111111111111112")).toBe(false);
    expect(passesLuhn("123")).toBe(false);
  });
});

describe("redactOutput", () => {
  it("replaces secrets with labels and leaves the rest intact", () => {
    const r = redactOutput(
      "key sk-abcdefghijklmnopqrstuvwxyz123456 and alice@example.com here",
    );
    expect(r.text).toBe(
      "key [REDACTED:API_KEY] and [REDACTED:EMAIL] here",
    );
    expect(r.redactions).toBe(2);
    expect(r.text).not.toContain("sk-");
    expect(r.text).not.toContain("alice@example.com");
  });

  it("leaves clean text unchanged with zero redactions", () => {
    const r = redactOutput("a clean reply");
    expect(r.text).toBe("a clean reply");
    expect(r.redactions).toBe(0);
  });

  it("redacts a long secret fully, not just its first 120 characters", () => {
    const longKey = `sk-${"a".repeat(150)}`;
    const r = redactOutput(`key ${longKey} end`);
    expect(r.text).toBe("key [REDACTED:API_KEY] end");
    expect(r.text).not.toContain("a".repeat(10));
  });
});
