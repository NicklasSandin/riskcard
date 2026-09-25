// Focused unit tests for src/score.js. Expected numbers below were derived
// by hand from the documented formulae in src/score.js (which are in turn
// verbatim from the exposure-risk-quantification skill, see
// docs/fullstack/riskcard-fair-adaptation.md) and cross-checked by running
// computeScore() directly against each input during test authoring.

import { test } from "node:test";
import assert from "node:assert/strict";
import { computeScore } from "../src/score.js";

function finding(overrides = {}) {
  return {
    tool: "test-tool",
    ruleId: "r1",
    severity: "medium",
    message: "",
    tags: [],
    securitySeverity: null,
    locations: [],
    ...overrides,
  };
}

test("score: empty findings array grades A with risk 0 and a 'nothing to grade' narrative", () => {
  const score = computeScore([]);
  assert.equal(score.risk, 0);
  assert.equal(score.grade, "A");
  assert.equal(score.exposure, 0);
  assert.equal(score.threat, 0);
  assert.equal(score.impact, 0);
  assert.equal(score.dominantDriver, "none");
  assert.match(score.narrative, /nothing to grade/i);
  assert.deepEqual(score.bySeverity, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
});

test("score: bySeverity tallies every severity bucket across a mixed finding set", () => {
  const score = computeScore([
    finding({ severity: "critical" }),
    finding({ severity: "critical" }),
    finding({ severity: "high" }),
    finding({ severity: "medium" }),
    finding({ severity: "low" }),
    finding({ severity: "info" }),
  ]);
  assert.deepEqual(score.bySeverity, { critical: 2, high: 1, medium: 1, low: 1, info: 1 });
});

test("score: a single critical finding with no credential/high-impact signal applies the proven-critical Exposure floor (E=0.5) and grades A at the boundary", () => {
  // S = 1.0 (one critical) -> E raw = 1-e^(-1/25) ~= 0.0392, floored to 0.5
  // by the proven-critical floor. T = combine([]) = 0 (no threat weights fire
  // for a generic, non-credential category). I = 0.4 baseline.
  // likelihood = combine([0.5, 0]) = 0.5; risk = 0.5 * 0.4 * 100 = 20.0 -> grade A (risk <= 20).
  const score = computeScore([finding({ severity: "critical" })]);
  assert.equal(score.exposure, 0.5);
  assert.equal(score.threat, 0);
  assert.equal(score.impact, 0.4);
  assert.equal(score.risk, 20);
  assert.equal(score.grade, "A");
  assert.equal(score.dominantDriver, "exposure");
});

test("score: a single high finding (no critical) does not trigger the Exposure floor and grades near-zero risk", () => {
  const score = computeScore([finding({ severity: "high" })]);
  assert.equal(score.exposure, 0.02);
  assert.equal(score.threat, 0);
  assert.equal(score.risk, 0.6);
  assert.equal(score.grade, "A");
});

test("score: Exposure accumulates with more findings of the same severity (breadth increases the score)", () => {
  const one = computeScore([finding({ severity: "high" })]);
  const three = computeScore([finding({ severity: "high" }), finding({ severity: "high" }), finding({ severity: "high" })]);
  assert.ok(three.exposure > one.exposure);
  assert.ok(three.risk > one.risk);
});

test("score: a critical credential-category finding drives Threat to 0.9 and Impact to 1.0, grading F", () => {
  const score = computeScore([
    finding({ severity: "critical", tags: ["cwe-798"], message: "hardcoded secret" }),
  ]);
  assert.equal(score.exposure, 0.5);
  assert.equal(score.threat, 0.9);
  assert.equal(score.impact, 1);
  assert.equal(score.risk, 95);
  assert.equal(score.grade, "F");
  assert.equal(score.dominantDriver, "threat");
});

test("score: a co-occurring credential + high-impact finding pair triggers the binary attack-path Threat weight (+0.6)", () => {
  const withoutPair = computeScore([finding({ severity: "critical", tags: ["cwe-798"], message: "hardcoded secret" })]);
  const withPair = computeScore([
    finding({ severity: "critical", tags: ["cwe-798"], message: "hardcoded secret" }),
    finding({ severity: "high", tags: ["cwe-89"], message: "sql injection" }),
  ]);
  assert.equal(withPair.threat, 0.96);
  assert.ok(withPair.threat > withoutPair.threat);
  assert.equal(withPair.risk, 98);
  assert.equal(withPair.grade, "F");
});

test("score: a high securitySeverity alone (no critical severity label) still raises Threat via the CVSS-proxy term", () => {
  // maxSecuritySeverity 9.5 -> min(1, 9.5/10) * 0.7 = 0.665, combine([0.665]) = 0.665
  // (rounded in output to 2dp: 0.66... let's assert via the computed field directly)
  const score = computeScore([finding({ severity: "medium", securitySeverity: 9.5 })]);
  assert.equal(score.threat, 0.66);
  assert.equal(score.risk, 26.7);
  assert.equal(score.grade, "B");
  assert.equal(score.dominantDriver, "threat");
});

test("score: grade bands are monotonic — more/worse findings never produce a better grade", () => {
  const light = computeScore([finding({ severity: "low" })]);
  const heavy = computeScore([
    finding({ severity: "critical", tags: ["cwe-798"], message: "hardcoded secret" }),
    finding({ severity: "critical", tags: ["cwe-89"], message: "sql injection" }),
  ]);
  const order = ["A", "B", "C", "D", "F"];
  assert.ok(order.indexOf(heavy.grade) >= order.indexOf(light.grade));
  assert.ok(heavy.risk > light.risk);
});

test("score: dominantDriver reports 'exposure' when Exposure >= Threat, and 'threat' when Threat is larger", () => {
  const exposureDriven = computeScore([finding({ severity: "critical" })]); // E=0.5, T=0
  const threatDriven = computeScore([finding({ severity: "critical", tags: ["cwe-798"], message: "hardcoded secret" })]); // E=0.5, T=0.9
  assert.equal(exposureDriven.dominantDriver, "exposure");
  assert.equal(threatDriven.dominantDriver, "threat");
});

test("score: risk is rounded to one decimal place", () => {
  const score = computeScore([finding({ severity: "medium", securitySeverity: 9.5 })]);
  assert.equal(Math.round(score.risk * 10) / 10, score.risk);
});
