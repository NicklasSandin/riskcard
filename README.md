# riskcard

A free, open-source, **zero-dependency** command-line tool (and GitHub
Action) that turns SARIF 2.1.0 scanner output — [Trivy](https://github.com/aquasecurity/trivy),
[Semgrep](https://semgrep.dev), [CodeQL](https://codeql.github.com),
[Grype](https://github.com/anchore/grype), and anything else that emits
SARIF 2.1.0 — into two things a raw finding list doesn't give you:

- **A composite 0–100 risk score and letter grade (A–F)**, using a
  three-factor FAIR-style model (Exposure × Threat → Likelihood, ×
  Impact → Risk).
- **A dollar-range annualized loss estimate** (e.g. `$135,000–$180,000`),
  based on IBM/Ponemon per-record breach-cost data, scaled by your findings.

Runs entirely offline. No network calls, no signup, no account — it reads
the SARIF file (and optional config file) you give it, and nothing else.

## This is an automated, unaudited estimate — read this before you use the number

**riskcard does not know your business.** It cannot tell you how many
customer records are actually at risk, what your industry's real breach
cost looks like, or whether a finding is exploitable in your specific
deployment. Every report it produces carries this disclaimer, baked into
the artifact itself, not a link you have to click through to see:

> This report is an automated, unaudited estimate generated without human
> review. It is not a substitute for a professional risk assessment. The
> dollar figure shown is a modeled RANGE, not a precise measurement of
> your actual loss exposure. Do not use this report as the sole basis for
> a compliance attestation, insurance disclosure, board risk report, or
> customer security questionnaire without independent validation by a
> qualified analyst.

If you take one thing from this README: the range is a starting point for
a conversation with someone who understands your business, not a number
to paste into a document that leaves your team.

## What this is *not*

- **Not a scanner.** riskcard performs no scanning itself. It reads the
  SARIF output your CI already produces from Trivy/Semgrep/CodeQL/Grype
  and reasons about that.
- **Not a precise loss measurement.** The dollar figure is always a range
  built from public industry cost bands (IBM/Ponemon), not a model of your
  actual breach history or business context — see
  [Methodology](#methodology) below.
- **Not a compliance or audit artifact.** Nothing here substitutes for a
  qualified analyst's review, a real FAIR assessment with your own loss
  data, or a professional risk assessment.
- **Not a PR-comment bot by default.** The GitHub Action writes to the job
  summary only unless you explicitly opt in to a PR comment — see
  [GitHub Action](#github-action) below for why.

## Install & run

No `npm install` step needed for the tool itself — zero runtime
dependencies. Clone and run directly with Node.js 18+:

```bash
git clone https://github.com/NicklasSandin/riskcard.git
cd riskcard
node bin/riskcard.js --in path/to/scan-results.sarif
```

### Options

```
riskcard --in <file.sarif> [options]

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
```

### Example

```bash
$ node bin/riskcard.js --in test/fixtures/trivy.sarif
# riskcard report: test/fixtures/trivy.sarif

**Composite risk score:** 95/100 (**F**)
**Estimated annualized loss exposure:** $135,000–$180,000 (expected ~$148,500)

> **Disclaimer:** This report is an automated, unaudited estimate generated
> without human review. It is not a substitute for a professional risk
> assessment. [...full disclaimer, unabridged, in every report...]

Composite risk 95/100 (grade F). Driven primarily by breach-likelihood
signals in this scan (severity/CVSS-proxy scores, and/or a
credential-exposure finding co-occurring with an injection-class finding).

## Findings by severity

| Severity | Count |
|---|---|
| critical | 2 |
| high     | 2 |
| medium   | 1 |
| low      | 0 |
| info     | 0 |

## Top findings

- **CRITICAL** `CVE-2023-12345` (Trivy) — app/package-lock.json — ...
- **CRITICAL** `AVD-AWS-0089` (Trivy) — infra/terraform.tfstate:17 —
  Hardcoded AWS access key detected in terraform state file. ...
- ...

## Methodology

- **Risk score (0–100, F):** three-factor FAIR-style model — Exposure
  (0.5) × Threat (0.9) combined into Likelihood, × Impact (1) → Risk.
  Dominant driver this scan: **threat**. ...
- **Loss estimate basis:** PLACEHOLDER estimate: no --config
  recordsAtRisk supplied, so this range assumes a conservative
  placeholder of 1,000 at-risk records x $150-200/record (IBM/Ponemon
  Cost of a Data Breach bands), annualized by this scan's Threat
  likelihood factor (90%). [...] supply a --config file with a
  recordsAtRisk field (your own data-inventory count) for an
  org-specific estimate.
- **Config used:** none — loss estimate is using the placeholder record
  count above. Pass `--config <file>` for an org-specific number.
```

That output was generated by running riskcard against the fixture file
checked into this repo at `test/fixtures/trivy.sarif` — the whole example
is reproducible in one command.

## GitHub Action

`action.yml` at the repo root wraps the same CLI logic (no reimplemented
scoring, no separate code path) for use as a step in your workflow.

**Default behavior: the report is written to the job summary
(`$GITHUB_STEP_SUMMARY`) only.** No comment is posted on your pull
request unless you turn that on yourself. This is a deliberate choice, not
an oversight: a dollar figure that appears automatically as a PR comment
is a dollar figure someone will screenshot into a Slack message or a board
deck before anyone's had a chance to sanity-check it. Making that step
opt-in keeps the default path safe without taking the feature away from
teams who want it.

<!-- TODO: replace <PIN_COMMIT_SHA> with the actual first-commit SHA after initial push -->

```yaml
name: risk-check
on: [pull_request]

permissions:
  contents: read

jobs:
  riskcard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ...your Trivy/Semgrep/CodeQL/Grype step here, producing results.sarif...

      - uses: NicklasSandin/riskcard@<PIN_COMMIT_SHA>
        with:
          sarif-file: results.sarif
          # config-file: risk-config.json   # optional, see Options above
          # post-pr-comment: 'true'         # optional, OFF by default — see below
```

> **Convenience / always-latest (less safe — not the recommended default):**
> `uses: NicklasSandin/riskcard@main` will also work, tracking the branch
> tip instead of a fixed commit. This is a supply-chain risk: `main` is a
> mutable ref, so a compromised or force-pushed branch changes what code
> runs in your pipeline without your workflow file changing at all.
> SHA-pinning (above) is the recommended usage for anything beyond local
> experimentation — the same discipline you'd apply to any other
> third-party Action.

### Action inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `sarif-file` | yes | — | Path to the SARIF 2.1.0 file to analyze. |
| `config-file` | no | *(none)* | Path to an optional JSON config file (`recordsAtRisk`, `industry`, `costPerRecord`) for an org-specific loss estimate. |
| `format` | no | `md` | `md` or `json` — format written to the job summary (and PR comment, if enabled). |
| `post-pr-comment` | no | `false` | **Opt-in.** Set to `'true'` to additionally post the report as a PR comment. Requires `github-token`. |
| `github-token` | no | *(none)* | Token used only when `post-pr-comment` is `'true'`. Typically `${{ secrets.GITHUB_TOKEN }}` with `pull-requests: write` permission. Unused otherwise. |

### Action outputs

| Output | Description |
|---|---|
| `risk-score` | Composite risk score, 0–100. |
| `grade` | Letter grade, A–F. |
| `loss-low` / `loss-expected` / `loss-high` | Estimated annualized loss exposure range, in USD. |

### Opting in to a PR comment

If you do want the report visible on the PR itself — a reasonable choice
for a team that's already agreed to review these numbers together — turn
it on explicitly and grant the token permission to write:

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  # ...scan step...
  - uses: NicklasSandin/riskcard@<PIN_COMMIT_SHA>
    with:
      sarif-file: results.sarif
      post-pr-comment: 'true'
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Methodology

riskcard reuses (does not reinvent) an existing three-factor FAIR-style
scoring model, adapted from an internal org-recon risk methodology to
SARIF's flat finding-list shape. In short:

- **Exposure (E):** a severity-weighted sum across every finding in the
  scan, saturating via `1 - e^(-S/25)`, with a floor if any finding is
  CRITICAL severity.
- **Threat (T):** an independent-evidence combiner over SARIF-native
  signals only — no live threat intel (no CISA KEV lookups, no EPSS API
  calls, no dark-web monitoring) because this tool makes no network calls,
  by design. It uses the finding's own `security-severity` score as an
  EPSS-shaped proxy, a CRITICAL-severity finding in a non-generic
  (credential or high-impact) category as a proxy for "proven
  exploitable," and same-scan co-occurrence of a
  credential finding with a high-impact finding as a proxy for "a
  credential exposure chains into an exploitable entry point."
- **Impact (I):** a worst-case ceiling driven by finding category —
  baseline 0.4, rising to 0.9 for high-impact classes (SQLi, XSS, SSRF,
  auth bypass, deserialization, etc.) and 1.0 if any finding is a
  hardcoded/leaked-credential class.
- **Risk = combine([E, T]) × I × 100**, mapped to a letter grade (A ≤ 20,
  B ≤ 40, C ≤ 60, D ≤ 80, F > 80).
- **Loss estimate:** `recordsAtRisk × cost-per-record (IBM/Ponemon
  bands)`, annualized by the Threat factor (not the composite risk score —
  those are deliberately not the same number). Without `--config`, a
  small, loudly-labeled placeholder record count (1,000) is used instead
  of silently omitting the figure, and the report says so explicitly.

Every constant and formula above is carried over unchanged from where a
direct analog exists; every place the SARIF input shape forces a
different computation (no asset graph, no live threat feeds, no
record-count field) is a disclosed, deliberate scope cut, not a silent
approximation. This tool will not fabricate a signal it doesn't have —
it either finds a real SARIF-native analog or drops the term and says so
in the report's basis string.

(The full internal mapping — a line-by-line comparison against the source
FAIR skill this was adapted from — lives in this company's internal docs
and isn't published in this repo; the summary above covers everything
that affects the number you'll actually see.)

## Only run this against SARIF from scans you were authorized to run

riskcard itself never touches your code or your network — it only reads a
SARIF file you already produced. The authorization boundary that matters
is upstream of this tool: the same rule that applies to running
Trivy/Semgrep/CodeQL/Grype in the first place.

## Why this exists, honestly

This is a new, small project from a small team. We're not asking you to
trust the dollar figure because of who made it — we don't have a track
record yet, and the whole point of the disclaimer above is that you
shouldn't outsource judgment to a free tool with no support and no human
review. We are asking you to read it: it's plain Node.js built-ins
(`node:fs`, `node:fs/promises`) plus the global `fetch` Node 20 ships
with, no dependencies, no build step, no `postinstall` script. You can
read the whole scoring path in `src/` in one sitting.

## Kill criterion

Same discipline as every other free tool from this team: a hard
2-cycle-post-launch checkpoint. If there's near-zero organic signal
(stars/issues/mentions from people who aren't the team), the honest call
is to say so and stop investing further, not to quietly keep polishing it.

## License

MIT — see [LICENSE](LICENSE).
