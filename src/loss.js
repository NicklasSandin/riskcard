// The $-loss model. Adapts the exposure-risk-quantification skill's §8
// loss model -- exposed-record count x IBM/Ponemon per-record cost band,
// annualized by the Threat factor (not the composite risk, per skill §8.3's
// explicit warning against conflating the two) -- to SARIF findings, which
// carry no "records" field the way the skill's leaked_credential findings
// do (skill §8.2: `evidence.employees` / `evidence.users`). A Trivy or
// Semgrep result has nothing resembling a record count.
//
// Rather than invent a records-per-finding multiplier out of thin air --
// which would be exactly the false-precision failure mode this whole
// project exists to avoid (docs/critic/cycle-riskcard-premortem.md §2) --
// riskcard asks for the one number it genuinely cannot infer from a SARIF
// file: an optional --config file with a `recordsAtRisk` field, sourced
// from the caller's own data inventory (ceo-bezos's go/no-go memo §3:
// "Ship an optional, local, zero-backend config... for asset-criticality/
// industry inputs that improves the estimate when present, and say plainly
// in the output when it's absent and the number is therefore a rougher
// default.").
//
// Without a config, riskcard falls back to a small, clearly-labeled
// placeholder record count and says so loudly in the basis string --
// never silently presents a guess as a measurement (skill §5, §12: "Do NOT
// fabricate a dollar figure... always ship the basis string and the range,
// not the bare point estimate.").

export const DEFAULT_COST_PER_RECORD = { low: 150, expected: 165, high: 200 }; // IBM/Ponemon, skill §8.1, verbatim

const PLACEHOLDER_RECORDS = 1000;

/**
 * @param {{recordsAtRisk: number|null, costPerRecord: {low:number,expected:number,high:number}, threat: number}} args
 */
export function estimateLoss({ recordsAtRisk, costPerRecord, threat }) {
  const usedPlaceholder = recordsAtRisk == null;
  const records = usedPlaceholder ? PLACEHOLDER_RECORDS : recordsAtRisk;
  const t = clamp01(threat);

  const sle = {
    low: records * costPerRecord.low,
    expected: records * costPerRecord.expected,
    high: records * costPerRecord.high,
  };

  const low = Math.round(sle.low * t);
  const expected = Math.round(sle.expected * t);
  const high = Math.round(sle.high * t);

  const basis = usedPlaceholder
    ? `PLACEHOLDER estimate: no --config recordsAtRisk supplied, so this range assumes a conservative placeholder of ${records.toLocaleString()} at-risk records x $${costPerRecord.low}-${costPerRecord.high}/record (IBM/Ponemon Cost of a Data Breach bands, via this company's exposure-risk-quantification methodology), annualized by this scan's Threat likelihood factor (${(t * 100).toFixed(0)}%). This is a rough, order-of-magnitude placeholder, NOT a measurement of your actual exposure -- supply a --config file with a recordsAtRisk field (your own data-inventory count) for an org-specific estimate.`
    : `${records.toLocaleString()} at-risk record(s) (from your supplied --config file) x $${costPerRecord.low}-${costPerRecord.high}/record (IBM/Ponemon Cost of a Data Breach bands), annualized by this scan's Threat likelihood factor (${(t * 100).toFixed(0)}%).`;

  return { records, usedPlaceholder, low, expected, high, basis };
}

function clamp01(n) {
  return Math.max(0, Math.min(1, n));
}
