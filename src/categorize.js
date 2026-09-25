// Maps a normalized finding onto one of riskcard's three impact categories.
//
// This adapts the exposure-risk-quantification skill's §7.3 asset-value
// categories (credential/secret assets score 1.0, intrusive-web categories
// like SQLi/SSRF/auth-bypass score 0.9, generic assets score 0.4) from
// org-recon findings -- which categorize by *hostname* tokens (pay.,
// internal-, vpn., etc.) -- to SARIF code-scanning findings, which have no
// hostname to token-match. Instead we match on two signals that are
// actually present in a SARIF file: CWE identifiers (reliably present in
// rule tags for CodeQL and Semgrep) and rule-id/message keywords (needed
// for Trivy, which tags dependency CVEs with a severity word, not a CWE).

const CREDENTIAL_CWE = new Set(["cwe-798", "cwe-321", "cwe-522", "cwe-259"]);

const HIGH_IMPACT_CWE = new Set([
  "cwe-89", // SQL injection
  "cwe-78", // OS command injection
  "cwe-79", // XSS
  "cwe-502", // deserialization
  "cwe-611", // XXE
  "cwe-918", // SSRF
  "cwe-287", // improper authentication
  "cwe-306", // missing authentication for critical function
  "cwe-284", // improper access control
  "cwe-94", // code injection
]);

const CREDENTIAL_KEYWORDS =
  /secret|credential|password|api[-_ ]?key|private[-_ ]?key|access[-_ ]?key|auth[-_ ]?token/i;

const HIGH_IMPACT_KEYWORDS =
  /sql injection|command injection|remote code execution|\brce\b|deserializ|ssrf|server-side request forgery|xxe|xml external entity|auth(?:entication|orization)? bypass|path traversal|directory traversal|arbitrary code execution/i;

/**
 * @param {{ruleId: string, message: string, tags: string[]}} finding
 * @returns {"credential"|"high-impact"|"generic"}
 */
export function categorize(finding) {
  const cwes = extractCwes(finding.tags || []);
  const haystack = `${finding.ruleId || ""} ${finding.message || ""}`;

  if (hasAny(cwes, CREDENTIAL_CWE) || CREDENTIAL_KEYWORDS.test(haystack)) {
    return "credential";
  }
  if (hasAny(cwes, HIGH_IMPACT_CWE) || HIGH_IMPACT_KEYWORDS.test(haystack)) {
    return "high-impact";
  }
  return "generic";
}

function extractCwes(tags) {
  const out = new Set();
  for (const tag of tags) {
    const m = /cwe-?(\d+)/i.exec(tag);
    if (m) out.add(`cwe-${m[1]}`);
  }
  return out;
}

function hasAny(set, candidates) {
  for (const c of set) if (candidates.has(c)) return true;
  return false;
}
