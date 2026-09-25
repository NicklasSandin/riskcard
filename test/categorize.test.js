// Focused unit tests for src/categorize.js.

import { test } from "node:test";
import assert from "node:assert/strict";
import { categorize } from "../src/categorize.js";

test("categorize: a credential CWE tag (bare 'cwe-798') categorizes as credential", () => {
  assert.equal(categorize({ ruleId: "r1", message: "", tags: ["cwe-798"] }), "credential");
});

test("categorize: a credential CWE tag in CodeQL/Semgrep's 'external/cwe/cwe-798' convention still matches", () => {
  assert.equal(categorize({ ruleId: "r1", message: "", tags: ["external/cwe/cwe-798"] }), "credential");
});

test("categorize: a credential CWE tag in upper case ('CWE-798') still matches", () => {
  assert.equal(categorize({ ruleId: "r1", message: "", tags: ["CWE-798"] }), "credential");
});

test("categorize: every listed credential CWE (798/321/522/259) categorizes as credential", () => {
  for (const cwe of ["798", "321", "522", "259"]) {
    assert.equal(categorize({ ruleId: "r1", message: "", tags: [`cwe-${cwe}`] }), "credential");
  }
});

test("categorize: a credential keyword in the message (no CWE tag) categorizes as credential", () => {
  assert.equal(categorize({ ruleId: "r1", message: "Hardcoded API key detected", tags: [] }), "credential");
  assert.equal(categorize({ ruleId: "r1", message: "leaked private key in repo", tags: [] }), "credential");
  assert.equal(categorize({ ruleId: "r1", message: "password stored in plaintext", tags: [] }), "credential");
});

test("categorize: a credential keyword in the ruleId (no CWE tag, no message hit) categorizes as credential", () => {
  assert.equal(categorize({ ruleId: "hardcoded-secret-detector", message: "", tags: [] }), "credential");
});

test("categorize: a high-impact CWE tag (SQLi, cwe-89) categorizes as high-impact", () => {
  assert.equal(categorize({ ruleId: "r1", message: "", tags: ["cwe-89"] }), "high-impact");
});

test("categorize: every listed high-impact CWE categorizes as high-impact", () => {
  const cwes = ["89", "78", "79", "502", "611", "918", "287", "306", "284", "94"];
  for (const cwe of cwes) {
    assert.equal(categorize({ ruleId: "r1", message: "", tags: [`cwe-${cwe}`] }), "high-impact");
  }
});

test("categorize: a high-impact keyword in the message (no CWE tag) categorizes as high-impact", () => {
  assert.equal(categorize({ ruleId: "r1", message: "possible SQL injection here", tags: [] }), "high-impact");
  assert.equal(categorize({ ruleId: "r1", message: "SSRF via unchecked URL", tags: [] }), "high-impact");
  assert.equal(categorize({ ruleId: "r1", message: "classic path traversal bug", tags: [] }), "high-impact");
});

test("categorize: a finding with neither credential nor high-impact signals is generic", () => {
  assert.equal(
    categorize({ ruleId: "unused-variable", message: "This variable is never read.", tags: ["maintainability"] }),
    "generic"
  );
});

test("categorize: credential is checked before high-impact — a finding matching both categorizes as credential", () => {
  assert.equal(
    categorize({
      ruleId: "r1",
      message: "hardcoded credential enables SQL injection bypass",
      tags: ["cwe-798", "cwe-89"],
    }),
    "credential"
  );
});

test("categorize: missing tags/message fields do not throw (defensive defaults)", () => {
  assert.equal(categorize({ ruleId: "r1" }), "generic");
  assert.equal(categorize({}), "generic");
});

test("categorize: a CWE number embedded in an unrelated tag string still extracts correctly", () => {
  assert.equal(categorize({ ruleId: "r1", message: "", tags: ["external/cwe/cwe-89/sql-injection"] }), "high-impact");
});
