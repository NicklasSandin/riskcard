// Focused unit tests for src/args.js.

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../src/args.js";

test("args: defaults when given no arguments", () => {
  const args = parseArgs([]);
  assert.deepEqual(args, { in: null, out: null, format: "md", config: null, help: false, version: false });
});

test("args: parses --in, --out, --format, --config", () => {
  const args = parseArgs(["--in", "a.sarif", "--out", "report.md", "--format", "json", "--config", "c.json"]);
  assert.equal(args.in, "a.sarif");
  assert.equal(args.out, "report.md");
  assert.equal(args.format, "json");
  assert.equal(args.config, "c.json");
});

test("args: --format defaults to md when not given", () => {
  const args = parseArgs(["--in", "a.sarif"]);
  assert.equal(args.format, "md");
});

test("args: --format rejects anything other than md or json", () => {
  assert.throws(() => parseArgs(["--format", "yaml"]), /--format must be "md" or "json"/);
});

test("args: -h and --help both set help", () => {
  assert.equal(parseArgs(["-h"]).help, true);
  assert.equal(parseArgs(["--help"]).help, true);
});

test("args: -v and --version both set version", () => {
  assert.equal(parseArgs(["-v"]).version, true);
  assert.equal(parseArgs(["--version"]).version, true);
});

test("args: an unrecognized flag throws, naming the offending argument", () => {
  assert.throws(() => parseArgs(["--nope"]), /Unknown argument: --nope/);
});

test("args: a flag at the end of argv with no value yields undefined for that field, not a throw", () => {
  const args = parseArgs(["--in"]);
  assert.equal(args.in, undefined);
});

test("args: order of flags does not matter", () => {
  const a = parseArgs(["--format", "json", "--in", "x.sarif"]);
  const b = parseArgs(["--in", "x.sarif", "--format", "json"]);
  assert.deepEqual(a, b);
});
