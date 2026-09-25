// Renders scan results as markdown (stdout by default, or a file via
// --out) or JSON. No template engine, no HTML -- plain string building,
// consistent with the zero-dependency posture of the whole tool.
//
// Both renderers are the enforcement point for two of the five mandatory
// scope requirements set by critic-munger's pre-mortem and the CEO/CFO
// sign-off:
//
//   - The disclaimer (src/disclaimer.js) is written into every artifact
//     unconditionally. There is no parameter on either function that can
//     omit it.
//   - The dollar figure is ALWAYS rendered as "$low-$high (expected ~$X)",
//     never a bare number -- see formatRange() below, the single choke
//     point both renderers go through for any dollar figure.

import { DISCLAIMER } from "./disclaimer.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const TOP_FINDINGS_LIMIT = 10;

function formatMoney(n) {
  return `$${Math.round(n).toLocaleString("en-US")}`;
}

/** The one place a dollar figure is ever turned into a string. Always a range. */
function formatRange(low, high) {
  return `${formatMoney(low)}–${formatMoney(high)}`;
}

function severityRank(sev) {
  const i = SEVERITY_ORDER.indexOf(sev);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function truncate(str, n) {
  const s = (str || "").replace(/\s+/g, " ").trim();
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export function renderMarkdown({ input, findings, score, loss, config }) {
  const lines = [];

  lines.push(`# riskcard report: ${input}`);
  lines.push("");
  lines.push(`**Composite risk score:** ${score.risk}/100 (**${score.grade}**)`);
  lines.push(
    `**Estimated annualized loss exposure:** ${formatRange(loss.low, loss.high)} (expected ~${formatMoney(loss.expected)})`
  );
  lines.push("");
  lines.push(`> **Disclaimer:** ${DISCLAIMER}`);
  lines.push("");
  lines.push(score.narrative);
  lines.push("");

  lines.push("## Findings by severity");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  for (const sev of SEVERITY_ORDER) lines.push(`| ${sev} | ${score.bySeverity[sev] || 0} |`);
  lines.push("");

  lines.push("## Top findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("(none)");
  } else {
    const top = [...findings]
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
      .slice(0, TOP_FINDINGS_LIMIT);
    for (const f of top) {
      const loc = f.locations[0] ? `${f.locations[0].file}${f.locations[0].line ? `:${f.locations[0].line}` : ""}` : "(no location)";
      lines.push(`- **${f.severity.toUpperCase()}** \`${f.ruleId}\` (${f.tool}) — ${loc} — ${truncate(f.message, 140)}`);
    }
    if (findings.length > TOP_FINDINGS_LIMIT) {
      lines.push(`- ...and ${findings.length - TOP_FINDINGS_LIMIT} more finding(s).`);
    }
  }
  lines.push("");

  lines.push("## Methodology");
  lines.push("");
  lines.push(
    `- **Risk score (0–100, ${score.grade}):** three-factor FAIR-style model — Exposure (${score.exposure}) × Threat (${score.threat}) combined into Likelihood, × Impact (${score.impact}) → Risk. Dominant driver this scan: **${score.dominantDriver}**. Reuses the formulae and constants of this company's \`exposure-risk-quantification\` skill, adapted from org-recon findings to SARIF code-scanning findings — see the project README for the full mapping.`
  );
  lines.push(
    `- **Loss estimate basis:** ${loss.basis}`
  );
  if (config?.source) {
    lines.push(`- **Config used:** \`${config.source}\`${config.industry ? ` (industry: ${config.industry})` : ""}`);
  } else {
    lines.push("- **Config used:** none — loss estimate is using the placeholder record count above. Pass `--config <file>` for an org-specific number.");
  }
  lines.push("");

  lines.push("---");
  lines.push(
    "_riskcard grades what's in the SARIF file you gave it. It does not scan anything itself, does not make network calls, and does not know your business context unless you supply `--config`._"
  );

  return lines.join("\n") + "\n";
}

export function renderJsonReport({ input, findings, score, loss, config }) {
  const payload = {
    input,
    disclaimer: DISCLAIMER,
    risk: score.risk,
    grade: score.grade,
    exposure: score.exposure,
    threat: score.threat,
    impact: score.impact,
    dominantDriver: score.dominantDriver,
    narrative: score.narrative,
    bySeverity: score.bySeverity,
    findingCount: findings.length,
    loss: {
      rangeLow: loss.low,
      rangeExpected: loss.expected,
      rangeHigh: loss.high,
      rangeLabel: `${formatMoney(loss.low)}–${formatMoney(loss.high)}`,
      records: loss.records,
      usedPlaceholderRecords: loss.usedPlaceholder,
      basis: loss.basis,
    },
    config: { source: config?.source ?? null, industry: config?.industry ?? null },
    findings,
  };
  return JSON.stringify(payload, null, 2) + "\n";
}
