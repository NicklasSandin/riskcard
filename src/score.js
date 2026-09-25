// Adapts the exposure-risk-quantification skill's §7 three-factor FAIR
// model -- Exposure x Threat -> Likelihood, x Impact -> Risk -- from
// org-recon findings to SARIF code-scanning findings. Every constant and
// formula below is reused VERBATIM from the skill wherever a direct analog
// exists; every place this file departs from the skill is called out in a
// comment at the point of departure. See docs/fullstack/riskcard-fair-adaptation.md
// for the full mapping table reviewed against the skill document.
//
// The single structural adaptation underlying all three factors: the
// skill's model gates heavily on *ownership* (is this asset confidently
// the target's?) because org-recon findings can land on infrastructure
// that isn't the target's at all. A SARIF file has no such ambiguity --
// every finding in it is on the repository the caller pointed the scanner
// at, i.e. their own code. So riskcard treats every finding as owned at
// the skill's owner_confidence=100 / CONFIRMED tier by construction, and
// none of the ownership-demotion machinery in skill §7.5 applies here.

import { categorize } from "./categorize.js";

const SEVERITY_WEIGHT = { critical: 1.0, high: 0.4, medium: 0.1, low: 0.02, info: 0.0 }; // skill §7.1, verbatim
const K = 25; // skill §7.1 calibration constant, verbatim

const GRADE_BANDS = [
  [20, "A"],
  [40, "B"],
  [60, "C"],
  [80, "D"],
  [Infinity, "F"],
]; // skill §7.4, verbatim

/**
 * The independent-evidence combiner, skill §7 / verbatim:
 * combine(weights) = 1 - Π(1 - w_i), each w_i clamped to [0,1].
 */
function combine(weights) {
  return 1 - weights.reduce((acc, w) => acc * (1 - clamp01(w)), 1);
}

function clamp01(n) {
  return Math.max(0, Math.min(1, n));
}

function gradeFor(risk) {
  for (const [max, letter] of GRADE_BANDS) if (risk <= max) return letter;
  return "F";
}

/**
 * @param {Array<object>} findings - normalized findings from src/sarif.js
 */
export function computeScore(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  if (findings.length === 0) {
    return {
      risk: 0,
      grade: "A",
      exposure: 0,
      threat: 0,
      impact: 0,
      dominantDriver: "none",
      bySeverity,
      narrative: "No findings in the supplied SARIF file -- nothing to grade.",
    };
  }

  // --- Exposure (E): severity-weighted breadth of the surface. Skill §7.1. ---
  const S = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
  let E = Math.min(1 - Math.exp(-S / K), 1 - 1e-15);

  const hasCritical = bySeverity.critical > 0;
  if (hasCritical) {
    // Proven-critical floor, skill §7.1: "if the scan carries an owned
    // (owner_confidence >= 70) finding that is severity CRITICAL... E =
    // max(E, 0.5)." Every finding here is owned by construction (see file
    // header), so the floor applies on any critical finding directly,
    // rather than gating on a separate ownership check the way the
    // org-recon skill must.
    E = Math.max(E, 0.5);
  }

  // --- Threat (T): breach-likelihood proxy. Skill §7.2, adapted. ---
  const categorized = findings.map((f) => ({ f, cat: categorize(f) }));
  const weights = [];

  const ownedProvenCritical = categorized.some(
    ({ f, cat }) => f.severity === "critical" && cat !== "generic"
  );
  if (ownedProvenCritical) {
    // Analog of skill §7.2's "proven exploit on an owned host, OR an owned
    // CONFIRMED/proven critical" -> weight 0.90. A CRITICAL finding in a
    // credential- or injection-class category, on code the caller owns by
    // construction, stands in for that signal.
    weights.push(0.9);
  }

  const maxSecuritySeverity = findings.reduce(
    (max, f) => (f.securitySeverity != null ? Math.max(max, f.securitySeverity) : max),
    0
  );
  if (maxSecuritySeverity > 0) {
    // Analog of skill §7.2's EPSS term: `min(1, epss_max) x 0.7`. riskcard
    // makes no live network call (no EPSS/KEV lookup -- zero-dependency,
    // offline by design), so the closest exploitability proxy actually
    // present inside the SARIF file itself is `security-severity`, a 0-10
    // CVSS-like float. Scaled onto the same [0,1] x 0.7 shape.
    weights.push(Math.min(1, maxSecuritySeverity / 10) * 0.7);
  }

  const hasCriticalOrHighCredential = categorized.some(
    ({ f, cat }) => cat === "credential" && (f.severity === "critical" || f.severity === "high")
  );
  const hasCriticalOrHighImpact = categorized.some(
    ({ f, cat }) => cat === "high-impact" && (f.severity === "critical" || f.severity === "high")
  );
  if (hasCriticalOrHighCredential && hasCriticalOrHighImpact) {
    // Analog of skill §9.4's binary attack-path trigger (e.g.
    // admin_panel+leaked_cred fires a fixed +0.60 Threat weight once a
    // qualifying chain is present -- not proportional to how many chains,
    // or how severe). A credential-exposure finding co-occurring with an
    // injection/RCE-class finding anywhere in the same scan is the
    // SARIF-native equivalent: there's only one "asset" in scope (the
    // repo), so co-occurrence anywhere in the scan is the correct analog
    // of "for the same root domain."
    weights.push(0.6);
  }

  const T = combine(weights);

  // --- Impact (I): worst-case category found. Skill §7.3, adapted. ---
  // Baseline 0.4 mirrors the skill's generic webapp/subdomain asset
  // weight -- there is always at least one finding here, i.e. always at
  // least a baseline-value "asset" (the repo) in scope. No
  // owner_confidence scaling is applied (see file header: owner_confidence
  // = 100 by construction), so I is the raw category weight.
  let I = 0.4;
  if (categorized.some(({ cat }) => cat === "high-impact")) I = 0.9;
  if (categorized.some(({ cat }) => cat === "credential")) I = 1.0;

  const likelihood = combine([E, T]);
  const rawRisk = likelihood * I * 100;
  const risk = Math.round(rawRisk * 10) / 10; // skill §7.4: round(x, 1)
  const grade = gradeFor(risk);

  const dominantDriver = I < 0.2 ? "business-impact" : E >= T ? "exposure" : "threat";

  return {
    risk,
    grade,
    exposure: round2(E),
    threat: round2(T),
    impact: round2(I),
    dominantDriver,
    bySeverity,
    narrative: buildNarrative({ dominantDriver, bySeverity, risk, grade }),
  };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function buildNarrative({ dominantDriver, bySeverity, risk, grade }) {
  const parts = [`Composite risk ${risk}/100 (grade ${grade}).`];
  if (dominantDriver === "exposure") {
    parts.push(
      `Driven primarily by the breadth/severity of findings present (${bySeverity.critical} critical, ${bySeverity.high} high).`
    );
  } else if (dominantDriver === "threat") {
    parts.push(
      "Driven primarily by breach-likelihood signals in this scan (severity/CVSS-proxy scores, and/or a credential-exposure finding co-occurring with an injection-class finding)."
    );
  } else {
    parts.push(
      "Driven primarily by the business-impact ceiling -- no confidently-present credential- or injection-class finding to weight the estimate higher."
    );
  }
  return parts.join(" ");
}
