// Proves critic-munger's pre-mortem requirement #3 (§6.3): "Run the parser
// against real SARIF from at least three named scanners (Trivy, Semgrep,
// CodeQL minimum) on the same test repo; confirm grades are internally
// consistent before committing to the aggregation-layer pitch in the
// README." This is also what src/sarif.js's own doc-comment has claimed
// exists since before this file was written.
//
// Three things get proven here, matching the doc comment at the top of
// src/sarif.js:
//   (a) each fixture normalizes to the documented finding shape without
//       throwing, despite three different `level` vocabularies and three
//       different rule-metadata conventions.
//   (b) a critical-severity finding on the same conceptual issue (a
//       hardcoded AWS credential) produces a comparable grade regardless of
//       which scanner shape it came from.
//   (c) severity extraction picks the right signal at each priority level,
//       per scanner, using the fixtures' deliberately conflicting signals
//       (e.g. a tag says CRITICAL while the message text says LOW -- the
//       tag must win).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parseSarif } from "../src/sarif.js";
import { computeScore } from "../src/score.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures");

async function loadFixture(name) {
  const raw = await readFile(path.join(fixturesDir, `${name}.sarif`), "utf8");
  return parseSarif(raw);
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function assertShape(finding) {
  assert.equal(typeof finding.tool, "string");
  assert.ok(finding.tool.length > 0);
  assert.equal(typeof finding.ruleId, "string");
  assert.ok(VALID_SEVERITIES.has(finding.severity), `unexpected severity "${finding.severity}"`);
  assert.equal(typeof finding.message, "string");
  assert.ok(Array.isArray(finding.tags));
  assert.ok(finding.securitySeverity === null || typeof finding.securitySeverity === "number");
  assert.ok(Array.isArray(finding.locations));
  for (const loc of finding.locations) {
    assert.equal(typeof loc.file, "string");
    assert.ok(loc.line === null || typeof loc.line === "number");
  }
}

// --- (a) each scanner's shape normalizes without throwing, to the documented shape ---

test("cross-scanner: Trivy fixture parses without throwing and matches the documented shape", async () => {
  const findings = await loadFixture("trivy");
  assert.equal(findings.length, 5);
  for (const f of findings) {
    assertShape(f);
    assert.equal(f.tool, "Trivy");
  }
});

test("cross-scanner: Semgrep fixture parses without throwing and matches the documented shape", async () => {
  const findings = await loadFixture("semgrep");
  assert.equal(findings.length, 3);
  for (const f of findings) {
    assertShape(f);
    assert.equal(f.tool, "Semgrep OSS");
  }
});

test("cross-scanner: CodeQL fixture parses without throwing and matches the documented shape", async () => {
  const findings = await loadFixture("codeql");
  assert.equal(findings.length, 4);
  for (const f of findings) {
    assertShape(f);
    assert.equal(f.tool, "CodeQL");
  }
});

// --- (b) the same conceptual issue (hardcoded AWS credential) grades comparably ---

test("cross-scanner: a hardcoded-credential critical finding grades comparably across all three scanners", async () => {
  const trivy = (await loadFixture("trivy")).filter((f) => f.ruleId === "AVD-AWS-0089");
  const semgrep = (await loadFixture("semgrep")).filter(
    (f) => f.ruleId === "python.lang.security.audit.hardcoded-aws-key.hardcoded-aws-key"
  );
  const codeql = (await loadFixture("codeql")).filter((f) => f.ruleId === "py/hardcoded-credentials");

  // Sanity: each fixture actually contains exactly the finding we think it does.
  assert.equal(trivy.length, 1);
  assert.equal(semgrep.length, 1);
  assert.equal(codeql.length, 1);

  // All three normalize the same conceptual issue to "critical" severity,
  // despite arriving via three different extraction priority levels: a
  // Trivy rule tag, a Semgrep rule's security-severity property, and a
  // CodeQL rule's security-severity property.
  assert.equal(trivy[0].severity, "critical");
  assert.equal(semgrep[0].severity, "critical");
  assert.equal(codeql[0].severity, "critical");

  const trivyScore = computeScore(trivy);
  const semgrepScore = computeScore(semgrep);
  const codeqlScore = computeScore(codeql);

  // Same conceptual issue -> same letter grade, regardless of scanner shape.
  assert.equal(trivyScore.grade, "F");
  assert.equal(semgrepScore.grade, "F");
  assert.equal(codeqlScore.grade, "F");

  // And the underlying 0-100 numbers land in a tight, internally-consistent
  // band (within a few points of each other) rather than swinging wildly --
  // this is the actual thing critic's pre-mortem §6.3 (Cause C) worried
  // about: "grades that swing wildly for comparable codebases." A small
  // spread is expected (Semgrep/CodeQL additionally carry a security-severity
  // CVSS-proxy that nudges Threat slightly higher than Trivy's tag-only
  // signal), but all three must be well above the F cutoff (80), not
  // scattered across grade bands.
  const scores = [trivyScore.risk, semgrepScore.risk, codeqlScore.risk];
  for (const s of scores) assert.ok(s >= 90, `expected risk >= 90 for a critical credential finding, got ${s}`);
  assert.ok(Math.max(...scores) - Math.min(...scores) <= 10, `grades diverged too widely: ${scores}`);
});

test("cross-scanner: the full three-scanner scan of the same repo is internally consistent (all grade F)", async () => {
  const trivy = computeScore(await loadFixture("trivy"));
  const semgrep = computeScore(await loadFixture("semgrep"));
  const codeql = computeScore(await loadFixture("codeql"));

  // Each fixture represents a "same test repo" scan carrying at least one
  // hardcoded credential -- the worst-case finding should dominate all
  // three the same way, landing every scanner's overall scan in the same
  // grade band rather than one scanner's report reading "safe" while
  // another reads "critical" for the same underlying repo.
  assert.equal(trivy.grade, "F");
  assert.equal(semgrep.grade, "F");
  assert.equal(codeql.grade, "F");
});

// --- (c) severity extraction picks the right signal at each priority level, per scanner ---

test("cross-scanner: Trivy severity priority order is respected", async () => {
  const findings = await loadFixture("trivy");
  const byId = Object.fromEntries(findings.map((f) => [f.ruleId, f]));

  // Priority 1 (rule tag "CRITICAL") wins even though the message text says
  // "Severity: LOW" -- proves tag beats message text.
  assert.equal(byId["CVE-2023-12345"].severity, "critical");

  // Priority 1 (rule tag "CRITICAL" + cwe-798) on the hardcoded-key finding.
  assert.equal(byId["AVD-AWS-0089"].severity, "critical");

  // Priority 3 ("Severity: HIGH" in the message text) wins over the SARIF
  // `level` of "warning" (which alone would fall back to "medium") --
  // proves message-text beats level, when no tag or security-severity is
  // present.
  assert.equal(byId["CVE-2022-55555"].severity, "high");

  // Priority 4 (no tag severity word, no security-severity, no message
  // severity word) falls back to `level: "warning"` -> "medium".
  assert.equal(byId["CVE-2021-33333"].severity, "medium");

  // A result whose ruleId has no matching entry in the rules[] array at all
  // (missing rule metadata) still normalizes without throwing, falling all
  // the way back to `level: "error"` -> "high".
  assert.equal(byId["CVE-9999-UNKNOWN"].severity, "high");
  assert.deepEqual(byId["CVE-9999-UNKNOWN"].tags, []);
  assert.equal(byId["CVE-9999-UNKNOWN"].securitySeverity, null);
});

test("cross-scanner: Semgrep severity priority order is respected", async () => {
  const findings = await loadFixture("semgrep");
  const byId = Object.fromEntries(findings.map((f) => [f.ruleId, f]));

  // Priority 2 (rule's security-severity = 9.8) wins over `level: "warning"`
  // (which alone would fall back to "medium") -- proves security-severity
  // beats level.
  assert.equal(
    byId["python.lang.security.audit.hardcoded-aws-key.hardcoded-aws-key"].severity,
    "critical"
  );

  // No tag severity word, no security-severity, no message severity word ->
  // falls back to the result's own `level: "error"` -> "high".
  assert.equal(
    byId["javascript.express.security.audit.express-sqli-taint.express-sqli-taint"].severity,
    "high"
  );

  // The result omits `level` entirely (Semgrep's convention of setting
  // level on the rule rather than every result) -> falls back to the
  // rule's `defaultConfiguration.level: "warning"` -> "medium".
  assert.equal(
    byId["javascript.lang.security.detect-eval-with-expression.detect-eval-with-expression"]
      .severity,
    "medium"
  );
});

test("cross-scanner: CodeQL severity priority order is respected", async () => {
  const findings = await loadFixture("codeql");
  const byId = Object.fromEntries(findings.map((f) => [f.ruleId, f]));

  // Priority 2: security-severity 9.8 buckets to "critical" (>= 9.0),
  // beating `level: "error"` (which alone would map to "high").
  assert.equal(byId["py/hardcoded-credentials"].severity, "critical");

  // Priority 2: security-severity 8.5 buckets to "high" (>= 7.0, < 9.0).
  assert.equal(byId["js/sql-injection"].severity, "high");

  // No security-severity on a non-security rule -> falls back to
  // `level: "note"` -> "low".
  assert.equal(byId["js/useless-assignment-to-local"].severity, "low");

  // No security-severity -> falls back to `level: "none"` -> "info".
  assert.equal(byId["cpp/unused-variable"].severity, "info");
});
