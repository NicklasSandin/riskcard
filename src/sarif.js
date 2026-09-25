// SARIF 2.1.0 parser -> riskcard's normalized finding shape.
//
// Every finding this function emits has exactly this shape, regardless of
// which scanner produced the source file:
//
//   {
//     tool: string,               // run.tool.driver.name
//     ruleId: string,
//     severity: "critical"|"high"|"medium"|"low"|"info",
//     message: string,
//     tags: string[],             // rule.properties.tags, or []
//     securitySeverity: number|null,  // rule/result properties["security-severity"], 0-10
//     locations: [{file: string, line: number|null}],
//   }
//
// This is what mandatory scope requirement #4 (cross-scanner consistency)
// tests: test/cross-scanner.test.js proves a real Trivy-shaped SARIF file
// and a real Semgrep-shaped SARIF file both normalize into this exact
// shape, despite using different `level` vocabularies, different `rules`
// metadata conventions, and different (sometimes absent) `locations.region`
// nesting. See test/fixtures/trivy.sarif and test/fixtures/semgrep.sarif.
//
// Severity extraction is the trickiest part, because SARIF's own `level`
// field only has 4 values (error/warning/note/none) and different scanners
// collapse their real severity vocabulary into it inconsistently -- Trivy's
// "error" can mean CRITICAL or HIGH, and so can Semgrep's. Relying on
// `level` alone would silently misgrade findings. Priority order, most
// specific signal first:
//
//   1. An explicit severity word in the rule's own `properties.tags`
//      (Trivy's convention: tags end with "CRITICAL"/"HIGH"/"MEDIUM"/"LOW").
//   2. `properties["security-severity"]` -- a 0-10 CVSS-like float that
//      CodeQL/GHAS-integrated tools (and increasingly Semgrep) attach to
//      the rule for GitHub's own code-scanning severity display.
//   3. A "Severity: HIGH" style line embedded in the result message text
//      (Trivy embeds this directly in vulnerability messages).
//   4. SARIF `level` itself, falling back further to the rule's own
//      `defaultConfiguration.level` if the result omits `level` (Semgrep's
//      convention of setting level on the rule rather than every result).
//
// `level: "error"` is deliberately mapped to "high", not "critical" --
// it's genuinely ambiguous across tools, and manufacturing a CRITICAL
// grade from an ambiguous signal is exactly the false-precision failure
// mode this project exists to avoid (see docs/critic/cycle-riskcard-premortem.md §2).

const SEVERITY_KEYWORD_RE = /\b(critical|high|medium|low|info(?:rmational)?)\b/i;

const LEVEL_FALLBACK = { error: "high", warning: "medium", note: "low", none: "info" };

/**
 * @param {string} raw - raw SARIF file contents
 * @returns {Array<object>} normalized findings, see file header for shape
 */
export function parseSarif(raw) {
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Not valid JSON: ${err.message}`);
  }

  if (!doc || typeof doc !== "object" || !Array.isArray(doc.runs)) {
    throw new Error('Not a valid SARIF document: missing a top-level "runs" array.');
  }

  const findings = [];
  for (const run of doc.runs) {
    const toolName = run.tool?.driver?.name ?? "unknown-tool";
    const rulesById = buildRulesIndex(run);
    for (const result of run.results ?? []) {
      findings.push(normalizeResult(result, rulesById, toolName));
    }
  }
  return findings;
}

function buildRulesIndex(run) {
  const rules = run.tool?.driver?.rules ?? [];
  const byId = new Map();
  rules.forEach((rule, idx) => {
    if (rule.id) byId.set(rule.id, rule);
    byId.set(`#${idx}`, rule);
  });
  return byId;
}

function normalizeResult(result, rulesById, toolName) {
  const rule =
    (result.ruleId && rulesById.get(result.ruleId)) ||
    (result.ruleIndex != null && rulesById.get(`#${result.ruleIndex}`)) ||
    {};

  const message = result.message?.text ?? "";
  const tags = rule.properties?.tags ?? [];
  const securitySeverity = parseSecuritySeverity(
    rule.properties?.["security-severity"] ?? result.properties?.["security-severity"]
  );
  const severity = extractSeverity({
    tags,
    securitySeverity,
    message,
    level: result.level,
    ruleDefaultLevel: rule.defaultConfiguration?.level,
  });
  const locations = (result.locations ?? []).map(extractLocation).filter(Boolean);

  return {
    tool: toolName,
    ruleId: result.ruleId ?? "unknown-rule",
    severity,
    message,
    tags,
    securitySeverity,
    locations,
  };
}

function extractLocation(loc) {
  const phys = loc.physicalLocation;
  if (!phys) return null;
  const file = phys.artifactLocation?.uri ?? null;
  if (!file) return null;
  const line = phys.region?.startLine ?? null;
  return { file, line };
}

function parseSecuritySeverity(raw) {
  if (raw == null) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function extractSeverity({ tags, securitySeverity, message, level, ruleDefaultLevel }) {
  for (const tag of tags) {
    const m = SEVERITY_KEYWORD_RE.exec(tag);
    if (m) return normalizeSeverityWord(m[1]);
  }

  if (securitySeverity != null) return bucketSecuritySeverity(securitySeverity);

  const inMessage = SEVERITY_KEYWORD_RE.exec(message);
  if (inMessage) return normalizeSeverityWord(inMessage[1]);

  const lvl = level || ruleDefaultLevel || "warning";
  return LEVEL_FALLBACK[lvl] ?? "medium";
}

function normalizeSeverityWord(word) {
  const w = word.toLowerCase();
  return w.startsWith("info") ? "info" : w;
}

function bucketSecuritySeverity(score) {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}
