// Optional local, zero-backend config file loader. Plain JSON, no schema
// library -- consistent with the zero-dependency posture of the whole
// tool. See src/loss.js for why this exists: the one input riskcard
// genuinely cannot infer from a SARIF file (an at-risk record count) can
// be supplied here, from the caller's own data inventory.

import { readFile } from "node:fs/promises";
import { DEFAULT_COST_PER_RECORD } from "./loss.js";

/**
 * @param {string|null} path
 */
export async function loadConfig(path) {
  if (!path) {
    return {
      recordsAtRisk: null,
      industry: null,
      costPerRecord: DEFAULT_COST_PER_RECORD,
      source: null,
    };
  }

  const raw = await readFile(path, "utf8");
  let json;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Config file "${path}" is not valid JSON: ${err.message}`);
  }

  return {
    recordsAtRisk:
      typeof json.recordsAtRisk === "number" && json.recordsAtRisk >= 0 ? json.recordsAtRisk : null,
    industry: typeof json.industry === "string" ? json.industry : null,
    costPerRecord: isValidCostBand(json.costPerRecord) ? json.costPerRecord : DEFAULT_COST_PER_RECORD,
    source: path,
  };
}

function isValidCostBand(c) {
  return (
    c != null &&
    typeof c === "object" &&
    ["low", "expected", "high"].every((k) => typeof c[k] === "number" && c[k] >= 0)
  );
}
