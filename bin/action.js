#!/usr/bin/env node
// GitHub Action entrypoint (node20 runtime). A thin wrapper around the same
// library functions bin/riskcard.js calls -- it does not reimplement any
// scoring/loss/rendering logic, it just adapts CLI-shaped I/O (stdin/stdout,
// exit codes) to Action-shaped I/O (INPUT_* env vars, $GITHUB_STEP_SUMMARY,
// $GITHUB_OUTPUT, and, opt-in only, the GitHub REST API).
//
// Default behavior -- and this is load-bearing, not incidental -- is to
// write the report to the job summary ($GITHUB_STEP_SUMMARY) ONLY. This is
// the direct enforcement point for critic-munger's pre-mortem
// (docs/critic/cycle-riskcard-premortem.md §6, item 1): "Default output
// stays local -- no auto-posted PR/CI comment by default... this moves
// 'someone screenshots an unreviewed number into a board deck' from the
// default path to a deliberate choice." Posting a PR comment requires the
// caller to explicitly set post-pr-comment: 'true' AND supply a token.
//
// No dependencies: uses only node:fs/promises and the global fetch that
// ships with Node 20 -- consistent with the zero-dependency posture of the
// rest of this project.

import { readFile, appendFile } from "node:fs/promises";
import { parseSarif } from "../src/sarif.js";
import { computeScore } from "../src/score.js";
import { loadConfig } from "../src/config.js";
import { estimateLoss } from "../src/loss.js";
import { renderMarkdown, renderJsonReport } from "../src/report.js";

function getInput(name) {
  // Matches actions/toolkit's own convention: INPUT_<NAME>, uppercased,
  // spaces (not hyphens) turned into underscores.
  const key = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  const v = process.env[key];
  return v ? v.trim() : "";
}

async function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  await appendFile(file, `${name}=${value}\n`, "utf8");
}

function setFailed(message) {
  console.log(`::error::${message}`);
  process.exitCode = 1;
}

async function postPrComment(body) {
  const token = getInput("github-token") || process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!token) {
    console.log(
      "::warning::post-pr-comment is 'true' but no github-token input was provided -- skipping PR comment. Job summary was still written."
    );
    return;
  }
  if (!repo || !eventPath) {
    console.log(
      "::warning::post-pr-comment is 'true' but this run has no GITHUB_REPOSITORY/GITHUB_EVENT_PATH context -- skipping PR comment."
    );
    return;
  }

  let event;
  try {
    event = JSON.parse(await readFile(eventPath, "utf8"));
  } catch (err) {
    console.log(`::warning::could not read the event payload -- skipping PR comment (${err.message}).`);
    return;
  }

  const prNumber = event.pull_request?.number ?? event.number;
  if (!prNumber) {
    console.log(
      "::warning::post-pr-comment is 'true' but this run has no pull_request context (not a pull_request/pull_request_target event) -- skipping PR comment."
    );
    return;
  }

  const res = await fetch(`https://api.github.com/repos/${repo}/issues/${prNumber}/comments`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "riskcard-action",
    },
    body: JSON.stringify({ body }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    console.log(`::warning::failed to post PR comment (HTTP ${res.status}): ${text.slice(0, 500)}`);
  }
}

async function main() {
  const sarifPath = getInput("sarif-file");
  if (!sarifPath) {
    setFailed('Missing required input "sarif-file".');
    return;
  }

  const configPath = getInput("config-file") || null;
  const format = (getInput("format") || "md").toLowerCase();
  if (format !== "md" && format !== "json") {
    setFailed(`Input "format" must be "md" or "json", got "${format}".`);
    return;
  }
  const postPrCommentEnabled = getInput("post-pr-comment").toLowerCase() === "true";

  let raw;
  try {
    raw = await readFile(sarifPath, "utf8");
  } catch (err) {
    setFailed(`Could not read sarif-file "${sarifPath}": ${err.message}`);
    return;
  }

  let findings;
  try {
    findings = parseSarif(raw);
  } catch (err) {
    setFailed(`riskcard: ${err.message}`);
    return;
  }

  let config;
  try {
    config = await loadConfig(configPath);
  } catch (err) {
    setFailed(`riskcard: ${err.message}`);
    return;
  }

  const score = computeScore(findings);
  const loss = estimateLoss({
    recordsAtRisk: config.recordsAtRisk,
    costPerRecord: config.costPerRecord,
    threat: score.threat,
  });

  const data = { input: sarifPath, findings, score, loss, config };
  // The job summary and the (opt-in) PR comment always render the SAME
  // artifact -- this is the same "disclaimer lives in the artifact itself,
  // not a linked page" discipline src/report.js documents, just applied to
  // which surface(s) that artifact gets written to.
  const reportBody =
    format === "json" ? "```json\n" + renderJsonReport(data) + "```\n" : renderMarkdown(data);

  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, reportBody + "\n", "utf8");
  } else {
    // Not running under a real Actions runner (e.g. local testing) -- fall
    // back to stdout rather than silently doing nothing.
    process.stdout.write(reportBody);
  }

  await setOutput("risk-score", String(score.risk));
  await setOutput("grade", score.grade);
  await setOutput("loss-low", String(loss.low));
  await setOutput("loss-high", String(loss.high));
  await setOutput("loss-expected", String(loss.expected));

  if (postPrCommentEnabled) {
    await postPrComment(reportBody);
  }
}

main().catch((err) => {
  setFailed(err.stack || err.message);
});
