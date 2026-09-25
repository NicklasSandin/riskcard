#!/usr/bin/env node
// riskcard — a free, open-source, zero-dependency CLI that turns SARIF
// 2.1.0 scanner output (Trivy, Semgrep, CodeQL, Grype, etc.) into a
// FAIR-style dollar-range loss estimate and letter grade.
//
// Usage:
//   riskcard --in <file.sarif> [--out <file>] [--format md|json] [--config <file>]
//
// This tool performs no scanning itself. It only reads the SARIF file you
// give it and a local, optional config file — no network calls, nothing
// sent anywhere.

import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "../src/args.js";
import { parseSarif } from "../src/sarif.js";
import { computeScore } from "../src/score.js";
import { loadConfig } from "../src/config.js";
import { estimateLoss } from "../src/loss.js";
import { renderMarkdown, renderJsonReport } from "../src/report.js";

const HELP = `riskcard --in <file.sarif> [options]

Ingests SARIF 2.1.0 output (Trivy, Semgrep, CodeQL, Grype, etc.) and emits
a FAIR-style dollar-range loss estimate and letter grade.

This is an automated, unaudited estimate — not a substitute for a
professional risk assessment. Every report carries that disclaimer in
full; there is no flag to suppress it.

Options:
  --in <file>       Path to the SARIF 2.1.0 file to analyze (required)
  --out <file>      Write the report to a file instead of stdout
  --format md|json  Output format (default: md)
  --config <file>   Optional local JSON config ({ "recordsAtRisk": N,
                     "industry": "...", "costPerRecord": {low,expected,high} })
                     to improve the loss estimate. Without it, the loss
                     range uses a clearly-labeled placeholder.
  -h, --help        Show this help
  -v, --version     Show version
`;

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    process.exit(1);
    return;
  }

  if (args.help) {
    console.log(HELP);
    process.exit(0);
    return;
  }

  if (args.version) {
    const pkg = await import("../package.json", { with: { type: "json" } });
    console.log(pkg.default.version);
    process.exit(0);
    return;
  }

  if (!args.in) {
    console.error("Missing required argument: --in <file.sarif>\n");
    console.error(HELP);
    process.exit(1);
    return;
  }

  let raw;
  try {
    raw = await readFile(args.in, "utf8");
  } catch (err) {
    console.error(`riskcard: could not read "${args.in}": ${err.message}`);
    process.exit(1);
    return;
  }

  let findings;
  try {
    findings = parseSarif(raw);
  } catch (err) {
    console.error(`riskcard: ${err.message}`);
    process.exit(1);
    return;
  }

  let config;
  try {
    config = await loadConfig(args.config);
  } catch (err) {
    console.error(`riskcard: ${err.message}`);
    process.exit(1);
    return;
  }

  const score = computeScore(findings);
  const loss = estimateLoss({
    recordsAtRisk: config.recordsAtRisk,
    costPerRecord: config.costPerRecord,
    threat: score.threat,
  });

  const data = { input: args.in, findings, score, loss, config };
  const output = args.format === "json" ? renderJsonReport(data) : renderMarkdown(data);

  if (args.out) {
    await writeFile(args.out, output, "utf8");
    console.error(`Report written to ${args.out}`);
  } else {
    process.stdout.write(output);
  }
}

main().catch((err) => {
  console.error(`riskcard: fatal error: ${err.stack || err.message}`);
  process.exit(1);
});
