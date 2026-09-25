// Focused unit tests for src/loss.js — the $-loss model. Covers the
// no-config placeholder path (and that it's loudly labeled as a
// placeholder, per ceo-bezos's go/no-go memo §3 and critic-munger's
// pre-mortem §2), the supplied-config path, threat-factor annualization,
// and clamping.

import { test } from "node:test";
import assert from "node:assert/strict";
import { estimateLoss, DEFAULT_COST_PER_RECORD } from "../src/loss.js";

test("loss: with no recordsAtRisk supplied, falls back to the placeholder and says so in the basis string", () => {
  const loss = estimateLoss({ recordsAtRisk: null, costPerRecord: DEFAULT_COST_PER_RECORD, threat: 1 });
  assert.equal(loss.usedPlaceholder, true);
  assert.equal(loss.records, 1000);
  assert.match(loss.basis, /PLACEHOLDER/);
  assert.match(loss.basis, /--config/);
});

test("loss: with recordsAtRisk supplied, uses it exactly and does not label the basis as a placeholder", () => {
  const loss = estimateLoss({ recordsAtRisk: 5000, costPerRecord: DEFAULT_COST_PER_RECORD, threat: 1 });
  assert.equal(loss.usedPlaceholder, false);
  assert.equal(loss.records, 5000);
  assert.doesNotMatch(loss.basis, /PLACEHOLDER/);
  assert.match(loss.basis, /supplied --config file/);
});

test("loss: low/expected/high are records x cost-per-record x threat, each rounded", () => {
  const loss = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 1 });
  assert.equal(loss.low, 1000);
  assert.equal(loss.expected, 2000);
  assert.equal(loss.high, 3000);
});

test("loss: annualizes by the Threat factor, not by risk or any other number", () => {
  const full = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 1 });
  const half = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 0.5 });
  assert.equal(half.expected, full.expected / 2);
  assert.equal(half.low, full.low / 2);
  assert.equal(half.high, full.high / 2);
});

test("loss: threat of 0 zeroes out the entire range, but records/basis are still reported", () => {
  const loss = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 0 });
  assert.equal(loss.low, 0);
  assert.equal(loss.expected, 0);
  assert.equal(loss.high, 0);
  assert.equal(loss.records, 100);
});

test("loss: threat is clamped to [0, 1] even if given an out-of-range value", () => {
  const overOne = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 5 });
  const capped = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: 1 });
  assert.equal(overOne.expected, capped.expected);

  const negative = estimateLoss({ recordsAtRisk: 100, costPerRecord: { low: 10, expected: 20, high: 30 }, threat: -3 });
  assert.equal(negative.expected, 0);
});

test("loss: recordsAtRisk of 0 (a real, deliberate zero, not 'missing') is honored, not treated as a placeholder trigger", () => {
  const loss = estimateLoss({ recordsAtRisk: 0, costPerRecord: DEFAULT_COST_PER_RECORD, threat: 1 });
  assert.equal(loss.usedPlaceholder, false);
  assert.equal(loss.records, 0);
  assert.equal(loss.low, 0);
  assert.equal(loss.expected, 0);
  assert.equal(loss.high, 0);
});

test("loss: the basis string always names the cost-per-record band used", () => {
  const loss = estimateLoss({ recordsAtRisk: 10, costPerRecord: { low: 111, expected: 222, high: 333 }, threat: 1 });
  assert.match(loss.basis, /\$111-333\/record/);
});

test("loss: DEFAULT_COST_PER_RECORD matches the IBM/Ponemon band the skill documents ($150/165/200)", () => {
  assert.deepEqual(DEFAULT_COST_PER_RECORD, { low: 150, expected: 165, high: 200 });
});
