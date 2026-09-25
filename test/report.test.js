// Focused unit tests for src/report.js — this is the actual enforcement
// point for two mandatory requirements from critic-munger's pre-mortem
// (docs/critic/cycle-riskcard-premortem.md §6.2) and ceo-bezos's go/no-go
// memo (docs/ceo/cycle-riskcard-go-nogo.md §3):
//
//   1. Every rendered artifact carries the disclaimer, unconditionally.
//   2. A dollar loss figure is NEVER rendered as a bare number — always a
//      "$low-$high" range.
//
// These are tested directly against the rendered string/JSON output, not
// inferred from reading the source comments that claim it's enforced.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderMarkdown, renderJsonReport } from "../src/report.js";
import { DISCLAIMER } from "../src/disclaimer.js";

function baseData(overrides = {}) {
  return {
    input: "test.sarif",
    findings: [
      {
        tool: "Trivy",
        ruleId: "CVE-2023-1",
        severity: "critical",
        message: "A critical vulnerability",
        tags: [],
        securitySeverity: null,
        locations: [{ file: "app/foo.js", line: 10 }],
      },
      {
        tool: "Semgrep OSS",
        ruleId: "js.sqli",
        severity: "high",
        message: "Possible SQL injection",
        tags: [],
        securitySeverity: null,
        locations: [{ file: "app/db.js", line: null }],
      },
    ],
    score: {
      risk: 42.5,
      grade: "B",
      exposure: 0.4,
      threat: 0.3,
      impact: 0.9,
      dominantDriver: "threat",
      bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      narrative: "Composite risk 42.5/100 (grade B). Test narrative.",
    },
    loss: {
      records: 1000,
      usedPlaceholder: true,
      low: 100000,
      expected: 150000,
      high: 200000,
      basis: "PLACEHOLDER estimate: test basis string.",
    },
    config: { recordsAtRisk: null, industry: null, costPerRecord: { low: 150, expected: 165, high: 200 }, source: null },
    ...overrides,
  };
}

// --- disclaimer, unconditionally present ---

test("report(md): the disclaimer appears verbatim in the markdown report", () => {
  const md = renderMarkdown(baseData());
  assert.ok(md.includes(DISCLAIMER), "markdown output must contain the exact disclaimer text");
});

test("report(json): the disclaimer appears verbatim (and exactly) in the JSON report", () => {
  const payload = JSON.parse(renderJsonReport(baseData()));
  assert.equal(payload.disclaimer, DISCLAIMER);
});

test("report(md): the disclaimer still appears even with zero findings", () => {
  const md = renderMarkdown(baseData({ findings: [] }));
  assert.ok(md.includes(DISCLAIMER));
});

test("report(json): the disclaimer still appears even with zero findings", () => {
  const payload = JSON.parse(renderJsonReport(baseData({ findings: [] })));
  assert.equal(payload.disclaimer, DISCLAIMER);
});

test("report(md): the disclaimer survives an all-zero/no-config scan (the placeholder path)", () => {
  const md = renderMarkdown(
    baseData({
      score: {
        risk: 0,
        grade: "A",
        exposure: 0,
        threat: 0,
        impact: 0,
        dominantDriver: "none",
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        narrative: "No findings in the supplied SARIF file -- nothing to grade.",
      },
      loss: { records: 1000, usedPlaceholder: true, low: 0, expected: 0, high: 0, basis: "PLACEHOLDER estimate." },
      findings: [],
    })
  );
  assert.ok(md.includes(DISCLAIMER));
});

// --- dollar figures are always a range, never a bare number ---

test("report(md): the loss figure is rendered as a '$low-$high' range with an expected value, never a bare number", () => {
  const md = renderMarkdown(baseData());
  // formatMoney uses toLocaleString, so $100,000 not $100000.
  assert.match(md, /\$100,000–\$200,000/);
  assert.match(md, /expected ~\$150,000/);
});

test("report(md): the range renders even when low === high (a degenerate zero-width range is still a range, not collapsed to a bare figure)", () => {
  const md = renderMarkdown(baseData({ loss: { records: 0, usedPlaceholder: false, low: 0, expected: 0, high: 0, basis: "0 records." } }));
  assert.match(md, /\$0–\$0/);
});

test("report(json): rangeLabel is a formatted '$low-$high' string, and low/expected/high are all present alongside it (never just the point estimate)", () => {
  const payload = JSON.parse(renderJsonReport(baseData()));
  assert.equal(payload.loss.rangeLabel, "$100,000–$200,000");
  assert.equal(payload.loss.rangeLow, 100000);
  assert.equal(payload.loss.rangeExpected, 150000);
  assert.equal(payload.loss.rangeHigh, 200000);
});

test("report(md): large dollar figures use thousands separators", () => {
  const md = renderMarkdown(baseData({ loss: { records: 1000, usedPlaceholder: true, low: 1234567, expected: 1500000, high: 2000000, basis: "x" } }));
  assert.match(md, /\$1,234,567–\$2,000,000/);
});

// --- structural content ---

test("report(md): renders 'no findings' state clearly and a zeroed severity table", () => {
  const md = renderMarkdown(baseData({ findings: [] }));
  assert.match(md, /\(none\)/);
  assert.match(md, /\| critical \| 1 \|/); // bySeverity in this baseData still says 1 critical (score is independent of findings list in this test data)
});

test("report(md): more than 10 findings are truncated with a '...and N more' trailer", () => {
  const many = Array.from({ length: 13 }, (_, i) => ({
    tool: "Trivy",
    ruleId: `CVE-${i}`,
    severity: "low",
    message: `finding ${i}`,
    tags: [],
    securitySeverity: null,
    locations: [],
  }));
  const md = renderMarkdown(baseData({ findings: many }));
  assert.match(md, /\.\.\.and 3 more finding\(s\)\./);
});

test("report(md): exactly 10 findings does not add a truncation trailer", () => {
  const ten = Array.from({ length: 10 }, (_, i) => ({
    tool: "Trivy",
    ruleId: `CVE-${i}`,
    severity: "low",
    message: `finding ${i}`,
    tags: [],
    securitySeverity: null,
    locations: [],
  }));
  const md = renderMarkdown(baseData({ findings: ten }));
  assert.doesNotMatch(md, /more finding\(s\)/);
});

test("report(md): findings are listed worst-severity-first", () => {
  const findings = [
    { tool: "T", ruleId: "low1", severity: "low", message: "m", tags: [], securitySeverity: null, locations: [] },
    { tool: "T", ruleId: "crit1", severity: "critical", message: "m", tags: [], securitySeverity: null, locations: [] },
    { tool: "T", ruleId: "med1", severity: "medium", message: "m", tags: [], securitySeverity: null, locations: [] },
  ];
  const md = renderMarkdown(baseData({ findings }));
  const idxCrit = md.indexOf("crit1");
  const idxMed = md.indexOf("med1");
  const idxLow = md.indexOf("low1");
  assert.ok(idxCrit < idxMed && idxMed < idxLow, "expected critical before medium before low in the findings list");
});

test("report(md): when no config was supplied, says so explicitly instead of silently using the placeholder", () => {
  const md = renderMarkdown(baseData({ config: { recordsAtRisk: null, industry: null, costPerRecord: { low: 150, expected: 165, high: 200 }, source: null } }));
  assert.match(md, /Config used:\*\* none/);
});

test("report(md): when a config file was supplied, names it (and the industry, if given)", () => {
  const md = renderMarkdown(
    baseData({ config: { recordsAtRisk: 500, industry: "healthcare", costPerRecord: { low: 150, expected: 165, high: 200 }, source: "./riskcard.config.json" } })
  );
  assert.match(md, /Config used:.*riskcard\.config\.json/);
  assert.match(md, /industry: healthcare/);
});

test("report(json): findingCount matches the findings array length, independent of the score object", () => {
  const payload = JSON.parse(renderJsonReport(baseData({ findings: [] })));
  assert.equal(payload.findingCount, 0);
});

test("report(json): output is valid, parseable JSON with no trailing content", () => {
  const raw = renderJsonReport(baseData());
  assert.doesNotThrow(() => JSON.parse(raw));
});
