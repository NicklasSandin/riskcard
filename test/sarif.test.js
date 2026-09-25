// Focused unit tests for src/sarif.js beyond the cross-scanner fixtures:
// malformed input, structurally-invalid SARIF, empty documents, missing
// rule metadata, and each severity-extraction priority level in complete
// isolation (one signal present at a time, so there's no ambiguity about
// which branch fired).

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSarif } from "../src/sarif.js";

function sarifDoc(runs) {
  return JSON.stringify({ version: "2.1.0", runs });
}

function runWith({ rules = [], results = [], toolName = "TestTool" } = {}) {
  return [
    {
      tool: { driver: { name: toolName, rules } },
      results,
    },
  ];
}

// --- malformed / structurally invalid input ---

test("sarif: throws a clear error on invalid JSON", () => {
  assert.throws(() => parseSarif("{ not json"), /Not valid JSON/);
});

test("sarif: throws a clear error when top-level runs array is missing", () => {
  assert.throws(() => parseSarif(JSON.stringify({ version: "2.1.0" })), /missing a top-level "runs" array/);
});

test("sarif: throws a clear error when the document is not an object", () => {
  assert.throws(() => parseSarif(JSON.stringify(["not", "an", "object"])), /Not a valid SARIF document/);
  assert.throws(() => parseSarif(JSON.stringify(null)), /Not a valid SARIF document/);
});

test("sarif: throws a clear error when runs is present but not an array", () => {
  assert.throws(() => parseSarif(JSON.stringify({ version: "2.1.0", runs: "nope" })), /missing a top-level "runs" array/);
});

// --- empty documents ---

test("sarif: an empty runs array yields an empty findings array, not a throw", () => {
  const findings = parseSarif(sarifDoc([]));
  assert.deepEqual(findings, []);
});

test("sarif: a run with no results yields no findings for that run", () => {
  const findings = parseSarif(sarifDoc(runWith({ results: [] })));
  assert.deepEqual(findings, []);
});

test("sarif: a run missing the results key entirely does not throw", () => {
  const findings = parseSarif(
    JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "X" } } }] })
  );
  assert.deepEqual(findings, []);
});

// --- missing rule metadata / defaults ---

test("sarif: a result with no matching rule in rules[] still normalizes, with empty tags and null securitySeverity", () => {
  const findings = parseSarif(
    sarifDoc(runWith({ rules: [], results: [{ ruleId: "no-such-rule", level: "warning", message: { text: "hi" } }] }))
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "no-such-rule");
  assert.deepEqual(findings[0].tags, []);
  assert.equal(findings[0].securitySeverity, null);
  assert.equal(findings[0].severity, "medium"); // level "warning" fallback
});

test("sarif: a result with no ruleId at all falls back to 'unknown-rule'", () => {
  const findings = parseSarif(sarifDoc(runWith({ results: [{ level: "error", message: { text: "hi" } }] })));
  assert.equal(findings[0].ruleId, "unknown-rule");
});

test("sarif: a run with no tool.driver.name falls back to 'unknown-tool'", () => {
  const findings = parseSarif(
    JSON.stringify({
      version: "2.1.0",
      runs: [{ tool: {}, results: [{ ruleId: "r1", level: "error", message: { text: "hi" } }] }],
    })
  );
  assert.equal(findings[0].tool, "unknown-tool");
});

test("sarif: a result with no message.text defaults to an empty string, not a throw", () => {
  const findings = parseSarif(sarifDoc(runWith({ results: [{ ruleId: "r1", level: "error" }] })));
  assert.equal(findings[0].message, "");
});

test("sarif: rule lookup via ruleIndex works when ruleId is absent from the result", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "the-rule", properties: { tags: ["security", "HIGH"] } }],
        results: [{ ruleIndex: 0, message: { text: "hi" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "high");
});

// --- locations ---

test("sarif: a result with no locations yields an empty locations array", () => {
  const findings = parseSarif(sarifDoc(runWith({ results: [{ ruleId: "r1", level: "error", message: { text: "hi" } }] })));
  assert.deepEqual(findings[0].locations, []);
});

test("sarif: a location missing physicalLocation is filtered out, not left as null/undefined", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        results: [{ ruleId: "r1", level: "error", message: { text: "hi" }, locations: [{ notAPhysicalLocation: true }] }],
      })
    )
  );
  assert.deepEqual(findings[0].locations, []);
});

test("sarif: a location missing artifactLocation.uri is filtered out", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        results: [
          {
            ruleId: "r1",
            level: "error",
            message: { text: "hi" },
            locations: [{ physicalLocation: { region: { startLine: 5 } } }],
          },
        ],
      })
    )
  );
  assert.deepEqual(findings[0].locations, []);
});

test("sarif: a location with no region.startLine reports line: null", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        results: [
          {
            ruleId: "r1",
            level: "error",
            message: { text: "hi" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "foo.js" } } }],
          },
        ],
      })
    )
  );
  assert.deepEqual(findings[0].locations, [{ file: "foo.js", line: null }]);
});

// --- severity extraction priority order, one signal in isolation at a time ---

test("sarif priority 1: a rule tag severity word wins even when nothing else is present", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1", properties: { tags: ["security", "HIGH"] } }],
        results: [{ ruleId: "r1", message: { text: "no severity word here" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "high");
});

test("sarif priority 1 beats priority 2: a tag severity word wins over security-severity", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1", properties: { tags: ["security", "LOW"], "security-severity": "9.9" } }],
        results: [{ ruleId: "r1", level: "error", message: { text: "Severity: CRITICAL" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "low");
});

test("sarif priority 2: security-severity wins over message text and level when no tag word is present", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1", properties: { tags: ["security"], "security-severity": "9.5" } }],
        results: [{ ruleId: "r1", level: "note", message: { text: "Severity: LOW" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "critical");
});

test("sarif priority 2: security-severity can also live on result.properties instead of rule.properties", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1" }],
        results: [{ ruleId: "r1", level: "note", properties: { "security-severity": "8.0" }, message: { text: "" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "high"); // 8.0 buckets to high (>=7.0, <9.0)
});

test("sarif priority 3: a message-text severity word wins over level when no tag or security-severity is present", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1" }],
        results: [{ ruleId: "r1", level: "note", message: { text: "Vulnerability found. Severity: HIGH. Fix now." } }],
      })
    )
  );
  assert.equal(findings[0].severity, "high");
});

test("sarif priority 4: falls back to result.level when nothing else is present", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1" }],
        results: [{ ruleId: "r1", level: "error", message: { text: "no severity word" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "high");
});

test("sarif priority 4b: falls back to rule.defaultConfiguration.level when result.level is absent", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1", defaultConfiguration: { level: "note" } }],
        results: [{ ruleId: "r1", message: { text: "no severity word" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "low");
});

test("sarif priority 4 (final fallback): defaults to 'medium' when level, ruleDefaultLevel, and every other signal are all absent", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1" }],
        results: [{ ruleId: "r1", message: { text: "no severity word" } }],
      })
    )
  );
  assert.equal(findings[0].severity, "medium");
});

test("sarif: all four SARIF level values map through LEVEL_FALLBACK correctly", () => {
  const cases = [
    ["error", "high"],
    ["warning", "medium"],
    ["note", "low"],
    ["none", "info"],
  ];
  for (const [level, expected] of cases) {
    const findings = parseSarif(
      sarifDoc(
        runWith({
          rules: [{ id: "r1" }],
          results: [{ ruleId: "r1", level, message: { text: "no severity word" } }],
        })
      )
    );
    assert.equal(findings[0].severity, expected, `level "${level}" should map to "${expected}"`);
  }
});

test("sarif: securitySeverity bucket boundaries", () => {
  const cases = [
    ["9.0", "critical"],
    ["10.0", "critical"],
    ["8.9", "high"],
    ["7.0", "high"],
    ["6.9", "medium"],
    ["4.0", "medium"],
    ["3.9", "low"],
    ["0.0", "low"],
  ];
  for (const [score, expected] of cases) {
    const findings = parseSarif(
      sarifDoc(
        runWith({
          rules: [{ id: "r1", properties: { "security-severity": score } }],
          results: [{ ruleId: "r1", level: "note", message: { text: "" } }],
        })
      )
    );
    assert.equal(findings[0].severity, expected, `security-severity "${score}" should bucket to "${expected}"`);
  }
});

test("sarif: a non-numeric security-severity is treated as absent, not as 0", () => {
  const findings = parseSarif(
    sarifDoc(
      runWith({
        rules: [{ id: "r1", properties: { "security-severity": "not-a-number" } }],
        results: [{ ruleId: "r1", level: "error", message: { text: "" } }],
      })
    )
  );
  assert.equal(findings[0].securitySeverity, null);
  assert.equal(findings[0].severity, "high"); // falls through to level fallback
});

test("sarif: results across multiple runs and multiple tools are all included", () => {
  const doc = JSON.stringify({
    version: "2.1.0",
    runs: [
      { tool: { driver: { name: "ToolA" } }, results: [{ ruleId: "a1", level: "error", message: { text: "" } }] },
      { tool: { driver: { name: "ToolB" } }, results: [{ ruleId: "b1", level: "warning", message: { text: "" } }] },
    ],
  });
  const findings = parseSarif(doc);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((f) => f.tool),
    ["ToolA", "ToolB"]
  );
});
