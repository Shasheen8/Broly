<table>
<tr>
<td width="300">
<img src="assets/broly-logo.png" alt="Broly" width="280"/>
</td>
<td align="center">

# Broly

### CLI-first berserker code security scanner.

Secrets · SCA · SAST · Containers · SBOM. AI-powered findings. Run locally or in CI with one binary.

<a href="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml"><img src="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
<a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
<a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/badge/Release-latest-blue?style=flat" alt="Release"></a>
<a href="https://together.ai"><img src="https://img.shields.io/badge/Powered%20by-Together%20AI-blueviolet?style=flat" alt="Together AI"></a>

</td>
</tr>
</table>

---

## What It Does

| Scanner | Engine | AI Layer |
|---------|--------|----------|
| **Secrets** | [Titus](https://github.com/praetorian-inc/titus) · 487 rules · Hyperscan locally (Go regex in CI) | `--ai-filter-secrets` reduces false positives |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 20 ecosystems | `--ai-sca-reachability` · `--package-intelligence` for hallucinated deps |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3.5-9B` · 17 regex prefilter patterns | Slice-aware multi-file analysis · includes `Dockerfile`, `Containerfile`, and Compose files when `--sast` is enabled |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + [osv.dev](https://osv.dev) | Pulls and scans registry, local daemon, or tarball images · auto-discovers base images from Dockerfiles and Compose under scan targets |
| **License** | File-based detection · 13 license types | Only runs when `allowed_licenses` or `denied_licenses` is set in `.broly.yaml` |
| **SBOM** | [osv-scalibr](https://github.com/google/osv-scalibr) · 20 ecosystems | `broly sbom` · CycloneDX 1.5 or SPDX 2.3 with PURLs |

---

## Install

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
```

For fastest local secrets scanning, install [Vectorscan](https://github.com/VectorCamp/vectorscan) (Hyperscan). Without it, Broly falls back to the Go regex engine (same rules, slower):

```bash
brew install vectorscan                   # macOS
sudo apt-get install -y libhyperscan-dev  # Ubuntu / Debian
```

The reusable GitHub workflow installs Broly with `CGO_ENABLED=0`, so CI always uses the Go regex engine.

Or download a pre-built binary from [Releases](https://github.com/Shasheen8/Broly/releases).

SAST and AI features require a [Together AI](https://together.ai) API key:

```bash
export TOGETHER_API_KEY=your_key_here
```

---

## Usage

```bash
broly scan                                        # secrets + SCA + SAST (SAST needs TOGETHER_API_KEY)
broly scan /path/to/project                       # specific path

# Individual scanners
broly scan --secrets                              # secrets only
broly scan --sca                                  # SCA only
broly scan --sast                                 # SAST only (requires TOGETHER_API_KEY)

# AI enhancements
broly scan --ai-filter-secrets                    # filter secrets false positives with AI
broly scan --ai-sca-reachability                  # check if vulnerable deps are actually called
broly scan --package-intelligence                 # detect hallucinated/non-existent packages
broly scan --ai-triage                            # verdict (TP/FP) + fix suggestion per finding
broly scan --ai-triage --explain                  # + one-sentence attack scenario per finding
broly scan --ai-triage --adversarial              # + adversarial verify on critical SAST TPs
broly scan --ai-triage --exploit-chains           # + exploit chains linking cross-scanner TPs

# Container scanning (pulls and analyzes images — full OS package/CVE pass)
broly scan --container alpine:3.19                # explicit image: pull + scan
broly scan --container ./image.tar              # tarball
broly scan .                                      # default scan also walks targets for Dockerfile / Compose and pulls each referenced base image

# Output
broly scan -f json                                # JSON output
broly scan -f sarif -o results.sarif              # SARIF 2.1.0 for GitHub Code Scanning
broly scan --min-severity high                    # only high and critical

# SBOM
broly sbom                                        # CycloneDX 1.5 to stdout
broly sbom -f spdx -o sbom.json                   # SPDX 2.3 to file

# Config and suppression
broly scan --config .broly.yaml                   # project config; also activates license policy
broly scan --baseline .broly-baseline.yaml        # suppress known FPs / require specific findings
broly scan --incremental                          # skip unchanged SAST files since last run
```

> [!NOTE]
> **GitHub Actions security (zizmor)** is not in this repo — no `pkg/workflow` scanner and `broly-app` does not run workflow scans either. If `enable_workflow: true` is in `.broly.yaml`, `broly scan` exits with an error (the message mentions `broly-app`; that path is not implemented here). Use a hosted Broly deployment or another tool for Actions static analysis.

---

## Scanner Output

*Video for each scanner output coming soon.*

Each scanner outputs an aligned table in the terminal. Supports JSON (`-f json`), SARIF (`-f sarif`), and table (default).

### AI Triage

`--ai-triage` adds an AI verdict in the terminal table for **SAST and SCA** findings (secrets and container findings are not triaged in the CLI orchestrator):

- `TRUE_POSITIVE` or `FALSE_POSITIVE`
- confidence score
- short reasoning in the `ASSESSMENT / CONTEXT` column
- targeted remediation in the `TARGETED FIX` column, including a concrete code fix when the model has enough local context

`--ai-triage --explain` adds one more thing: a plain-language attack scenario or impact sentence. The table format stays the same, but each finding becomes more verbose.

#### Agentic Triage (auto-enabled)

When `--ai-triage` is used against a local directory (the default `.` target), high-severity SAST findings are automatically triaged with **agentic repo tool use**. The AI can read related files, search the repository, and trace cross-file data flow before deciding a verdict — instead of relying only on the visible code snippet.

Three tools are available to the model:

- `repo_file_read` — read any file in the repo with optional line range
- `repo_code_search` — search repo text (uses `git grep` when available)
- `repo_find_files` — find tracked files by basename pattern

The agent loop runs up to 5 rounds with a maximum of 8 tool executions. Tool results are capped at 16K characters. All file content is redacted for secrets before being returned to the model.

No extra flags are needed — agentic triage activates automatically when:

1. `--ai-triage` is enabled
2. The scan target is a directory (not a single file)
3. The finding is SAST with severity >= high

If the repo directory can't be opened (e.g., permission error), triage silently falls back to the non-agentic single-prompt mode.

Use:

```bash
broly scan . --ai-triage
broly scan . --ai-triage --explain
```

Rule of thumb:

- `--ai-triage` is better for day-to-day developer scans
- `--ai-triage --explain` is better for reviews, demos, and cases where you want the exploit path spelled out more clearly

Example difference:

```text
--ai-triage
| Critical | SQL injection in login query | TRUE_POSITIVE [HIGH] | Recommendation: Use a prepared statement. |
|          | Code: $query = "SELECT ..."  | User input is        | Code fix: $stmt = $db->prepare(...);      |
|          |                              | concatenated into a  |                                           |
|          |                              | SQL query.           |                                           |

--ai-triage --explain
| Critical | SQL injection in login query | TRUE_POSITIVE [HIGH] | Recommendation: Use a prepared statement. |
|          | Code: $query = "SELECT ..."  | User input is        | Code fix: $stmt = $db->prepare(...);      |
|          |                              | concatenated into a  |                                           |
|          |                              | SQL query.           |                                           |
|          |                              | An attacker can send |                                           |
|          |                              | ' OR 1=1 -- to       |                                           |
|          |                              | bypass login or dump |                                           |
|          |                              | data.                |                                           |
```

### Adversarial Verification

`--adversarial` adds a second AI pass on **critical SAST true positives only**. It requires `--ai-triage` (it runs after triage so it has verdicts to work with).

Two-stage process:

1. **Falsification filter** — fast single-prompt check: does the visible code directly disprove the finding? (hardcoded safe literal, code never reaches sink, visible upstream sanitization). If `DISPROVEN: YES`, the finding is immediately downgraded to `FALSE_POSITIVE` with `AdversarialVerdict: FALSIFIED`.

2. **Full adversarial verify** — if the falsification filter doesn't disprove it, an agent loop (≤3 rounds) with repo tools traces data flow across files, hunts for auth gates, framework protections, or test-only paths. Returns:
   - `CONFIRMED` — an external entry point can reach the sink with real impact (finding stays `TRUE_POSITIVE`)
   - `DISPUTED` — no reachable exploit path or visible defenses neutralize it (downgraded to `FALSE_POSITIVE`)

When a finding is downgraded, the verdict flips to `FALSE_POSITIVE` with `HIGH` confidence and the adversarial reason replaces the verdict reason. The table output shows `adversarial confirmed`, `adversarial disputed`, or `adversarial falsified` next to the verdict.

Use:

```bash
broly scan . --sast --ai-triage --adversarial
```

### Exploit Chains

`--exploit-chains` synthesizes multi-step attack narratives by linking 2-4 cross-scanner true positives. It requires `--ai-triage` (it builds on triage verdicts).

Eligibility: at least 2 high-confidence `TRUE_POSITIVE` findings (or adversarial-confirmed) from **different scanner types** — SAST plus SCA, Secrets, Container, or Workflow. Known malicious packages are always eligible.

The LLM is prompted with the eligible findings (capped at 30 by severity/priority) and returns up to 4 chains. Each chain is validated:

- Fingerprints must resolve to real findings (by fingerprint, rule ID, or prompt index)
- No invented files, lines, or packages
- Severity capped at the highest linked finding's severity
- No overlapping chains (each finding appears in at most one chain)

Findings in a chain get `ChainID` and `ChainedFrom` fields. Chains appear in JSON/SARIF output and in the terminal table as a `Exploit Chains` section with title, severity, steps, and narrative.

Use:

```bash
broly scan . --ai-triage --exploit-chains
```

---

## CI Integration

Run the **`broly` CLI** in GitHub Actions with the reusable workflow:

```yaml
jobs:
  security:
    uses: Shasheen8/Broly/.github/workflows/broly-scan.yml@main
    secrets:
      ai_api_key: ${{ secrets.AI_API_KEY }}
```

Inputs: `min_severity`, `scanners` (`all` | `sast` | `sca` | `secrets`), and `ai_triage`. On pull requests it runs **secrets + SCA** on the full tree (and **pulls base images** referenced in Dockerfiles/Compose, same as local `broly scan`), runs **SAST** on changed code files only when `ai_api_key` is set, uploads SARIF to the GitHub Security tab, and posts a **summary PR comment** (findings table only — no fix blocks or false-positive checkboxes). Push/workflow_dispatch runs a full-repo scan with the same scanner selection rules.

### Optional: `broly-app` (local GitHub App)

`cmd/broly-app` is a webhook server for testing the **full PR experience** locally. It is not the production hosted service (no DynamoDB, org registry, zizmor, etc.).

On each pull request it:

- Clones the PR head and runs **secrets + SCA** on the repo
- Runs **SAST** on changed code files only when `TOGETHER_API_KEY` is set (with AI triage enabled)
- Posts a **check run** (summary + file annotations) and a **PR comment** (severity table, triage verdicts, collapsible fix suggestions, false-positive checkboxes)

Checkboxes in the PR comment are handled by [`.github/workflows/feedback.yml`](.github/workflows/feedback.yml): a maintainer checks a box, and the workflow commits the fingerprint to `.broly-baseline.yaml` on the PR branch.

```bash
APP_ID=... PRIVATE_KEY_PATH=./broly.pem WEBHOOK_SECRET=... TOGETHER_API_KEY=... \
  go run ./cmd/broly-app
```

Use [smee.io](https://smee.io) to forward GitHub webhooks to your machine while developing.

---

## Configuration

### Config file

> [!TIP]
> `.broly.yaml` is loaded automatically from the repo root. CLI flags always override it.

```yaml
min_severity: low
exclude_paths:
  - vendor
  - .git
workers: 8
baseline_file: .broly-baseline.yaml                  # optional: suppress / require rules
path_strip_prefix: /home/runner/work/myrepo/myrepo   # optional: strip clone path from finding paths
additional_suppressions:                             # optional: suppress by fingerprint
  - "abc123..."

# Do not set enable_workflow: true — the CLI does not run zizmor

# License policy (findings only emitted when configured)
allowed_licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
denied_licenses:
  - GPL-3.0
  - AGPL-3.0
```

### Baseline

> [!NOTE]
> `suppress` silences known false positives. `require` asserts specific findings must be detected every scan. Missing entries cause a non-zero exit.

```yaml
suppress:
  - fingerprint: "abc123..."
    reason: "test fixture"

require:
  - rule_id: "SQL-INJECTION"
    file: "api/handlers.py"
    reason: "SQL injection in user lookup - must be detected"
```

### Inline suppression

```python
query = "SELECT * FROM users WHERE id = " + user_id  # broly:ignore
query = f"SELECT * FROM users WHERE id = {user_id}"  # broly:ignore SQL-INJECTION
```

---

## License

MIT. See [LICENSE](LICENSE).
