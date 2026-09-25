// The mandatory disclaimer. Baked into every output artifact (CLI markdown,
// CLI JSON, GitHub Action job summary) unconditionally -- there is no flag
// anywhere in this codebase to suppress it. Required by critic-munger's
// pre-mortem (docs/critic/cycle-riskcard-premortem.md §6.2): "A fixed,
// same-artifact disclaimer, not just a range... every output -- not a
// linked page, the artifact itself."
//
// Single source of truth: report.js imports this for both renderers so the
// wording can never drift between the markdown and JSON paths.

export const DISCLAIMER =
  "This report is an automated, unaudited estimate generated without human " +
  "review. It is not a substitute for a professional risk assessment. The " +
  "dollar figure shown is a modeled RANGE, not a precise measurement of " +
  "your actual loss exposure. Do not use this report as the sole basis for " +
  "a compliance attestation, insurance disclosure, board risk report, or " +
  "customer security questionnaire without independent validation by a " +
  "qualified analyst.";
