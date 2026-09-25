// Focused unit tests for src/config.js — the optional local, zero-backend
// config file loader.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { DEFAULT_COST_PER_RECORD } from "../src/loss.js";

async function withTempFile(contents, fn) {
  const dir = await mkdtemp(path.join(tmpdir(), "riskcard-config-test-"));
  const file = path.join(dir, "config.json");
  await writeFile(file, contents, "utf8");
  try {
    return await fn(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("config: with no path, returns defaults — null recordsAtRisk, null industry, default cost band, null source", async () => {
  const config = await loadConfig(null);
  assert.deepEqual(config, {
    recordsAtRisk: null,
    industry: null,
    costPerRecord: DEFAULT_COST_PER_RECORD,
    source: null,
  });
});

test("config: a valid config file's fields are parsed through", async () => {
  await withTempFile(
    JSON.stringify({ recordsAtRisk: 4200, industry: "fintech", costPerRecord: { low: 100, expected: 150, high: 250 } }),
    async (file) => {
      const config = await loadConfig(file);
      assert.equal(config.recordsAtRisk, 4200);
      assert.equal(config.industry, "fintech");
      assert.deepEqual(config.costPerRecord, { low: 100, expected: 150, high: 250 });
      assert.equal(config.source, file);
    }
  );
});

test("config: a config file with invalid JSON throws a clear, named error", async () => {
  await withTempFile("{ not valid json", async (file) => {
    await assert.rejects(() => loadConfig(file), /is not valid JSON/);
  });
});

test("config: a nonexistent config path rejects (propagates the fs error) rather than silently defaulting", async () => {
  await assert.rejects(() => loadConfig("/nonexistent/path/to/riskcard-config.json"));
});

test("config: a negative recordsAtRisk is rejected and falls back to null", async () => {
  await withTempFile(JSON.stringify({ recordsAtRisk: -5 }), async (file) => {
    const config = await loadConfig(file);
    assert.equal(config.recordsAtRisk, null);
  });
});

test("config: recordsAtRisk of exactly 0 is honored (a real value, not falsy-rejected)", async () => {
  await withTempFile(JSON.stringify({ recordsAtRisk: 0 }), async (file) => {
    const config = await loadConfig(file);
    assert.equal(config.recordsAtRisk, 0);
  });
});

test("config: a non-numeric recordsAtRisk falls back to null", async () => {
  await withTempFile(JSON.stringify({ recordsAtRisk: "a lot" }), async (file) => {
    const config = await loadConfig(file);
    assert.equal(config.recordsAtRisk, null);
  });
});

test("config: a malformed costPerRecord (missing a required key) falls back to the default cost band", async () => {
  await withTempFile(JSON.stringify({ costPerRecord: { low: 100, expected: 150 } }), async (file) => {
    const config = await loadConfig(file);
    assert.deepEqual(config.costPerRecord, DEFAULT_COST_PER_RECORD);
  });
});

test("config: a costPerRecord with a non-numeric field falls back to the default cost band", async () => {
  await withTempFile(JSON.stringify({ costPerRecord: { low: "cheap", expected: 150, high: 250 } }), async (file) => {
    const config = await loadConfig(file);
    assert.deepEqual(config.costPerRecord, DEFAULT_COST_PER_RECORD);
  });
});

test("config: a non-string industry falls back to null", async () => {
  await withTempFile(JSON.stringify({ industry: 12345 }), async (file) => {
    const config = await loadConfig(file);
    assert.equal(config.industry, null);
  });
});

test("config: an empty JSON object is valid and yields all-default field values (with source set)", async () => {
  await withTempFile("{}", async (file) => {
    const config = await loadConfig(file);
    assert.equal(config.recordsAtRisk, null);
    assert.equal(config.industry, null);
    assert.deepEqual(config.costPerRecord, DEFAULT_COST_PER_RECORD);
    assert.equal(config.source, file);
  });
});
