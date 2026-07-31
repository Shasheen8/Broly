<table>
<tr>
<td width="300">
<img src="assets/broly-logo.png" alt="Broly" width="280"/>
</td>
<td align="center">

# Broly

### CLI-first berserker code security scanner.

Secrets · SCA · SAST · Workflow · IaC · Containers · SBOM · Supply Chain. AI-powered findings. Run locally or in CI with one binary.

<a href="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml"><img src="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26.4-00ADD8?style=flat&logo=go" alt="Go"></a>
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
| **SAST** | [Together AI](https://together.ai) · `zai-org/GLM-5.2` · 17 regex prefilter patterns | Slice-aware multi-file analysis · includes `Dockerfile`, `Containerfile`, and Compose files when `--sast` is enabled |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + [osv.dev](https://osv.dev) | Pulls and scans registry, local daemon, or tarball images · auto-discovers base images from Dockerfiles and Compose under scan targets |
| **License** | File-based detection · 13 license types | Only runs when `allowed_licenses` or `denied_licenses` is set in `.broly.yaml` |
| **Workflow** | [zizmor](https://docs.zizmor.sh/) · GitHub Actions static analysis | `--workflow` scans `.github/workflows/` and composite actions |
| **IaC** | [checkov](https://www.checkov.io/) · Terraform, Kubernetes, Helm, CloudFormation | `--iac` with 1200+ mapped checks and severity alignment |
| **Supply Chain** | [depx](https://github.com/projectdiscovery/depx) · OpenSSF malicious-package audit | `--supply-chain` flags known-malicious dependencies (never baseline-suppressible) |
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
broly scan --workflow                             # GitHub Actions workflow scanning (auto-installs zizmor)
broly scan --iac                                  # IaC scanning: Terraform, K8s, Helm, CloudFormation (auto-installs checkov)
broly scan --supply-chain                         # audit deps against known-malicious package feeds (requires depx)

# AI enhancements
broly scan --ai-filter-secrets                    # filter secrets false positives with AI
broly scan --ai-sca-reachability                  # check if vulnerable deps are actually called
broly scan --package-intelligence                 # detect hallucinated/non-existent packages
broly scan --ai-triage                            # verdict (TP/FP) + fix suggestion per finding
broly scan --ai-triage --explain                  # + one-sentence attack scenario per finding
broly scan --ai-triage --adversarial              # + adversarial verify on critical SAST TPs
broly scan --ai-triage --exploit-chains           # + exploit chains linking cross-scanner TPs

# Vulnerability class focus (hunt specific bug classes)
broly scan . --sast --ai-triage --idor            # IDOR/BOLA only, with AI verdicts
broly scan . --sast --ai-triage --xss             # XSS only
broly scan . --sqli --rce                         # combine classes

# Container scanning (pulls and analyzes images - full OS package/CVE pass)
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
> **GitHub Actions security (zizmor)** and **IaC scanning (checkov)** auto-install on first use. Broly creates a Python venv at `~/.cache/broly/venv/` and `pip install`s the tools automatically. If you prefer to install them yourself: `pip install zizmor checkov`. The `--workflow` and `--iac` flags use the system-installed version if available, otherwise fall back to the venv.

---

## Scanner Output

*Video for each scanner output coming soon.*

Each scanner outputs an aligned table in the terminal. Supports JSON (`-f json`), SARIF (`-f sarif`), and table (default).

### AI Triage

`--ai-triage` adds an AI verdict in the terminal table for **SAST, SCA, and Workflow** findings (secrets, container, and IaC findings are not triaged in the CLI orchestrator):

- `TRUE_POSITIVE` or `FALSE_POSITIVE`
- confidence score
- short reasoning in the `ASSESSMENT / CONTEXT` column
- targeted remediation in the `TARGETED FIX` column, including a concrete code fix when the model has enough local context

`--ai-triage --explain` adds one more thing: a plain-language attack scenario or impact sentence. The table format stays the same, but each finding becomes more verbose.

#### Agentic Triage (auto-enabled)

When `--ai-triage` is used against a local directory (the default `.` target), high-severity SAST findings are automatically triaged with **agentic repo tool use**. The AI can read related files, search the repository, and trace cross-file data flow before deciding a verdict - instead of relying only on the visible code snippet.

Three tools are available to the model:

- `repo_file_read` - read any file in the repo with optional line range
- `repo_code_search` - search repo text (uses `git grep` when available)
- `repo_find_files` - find tracked files by basename pattern

The agent loop runs up to 5 rounds with a maximum of 8 tool executions. Tool results are capped at 16K characters. All file content is redacted for secrets before being returned to the model.

No extra flags are needed - agentic triage activates automatically when:

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

1. **Falsification filter** - fast single-prompt check: does the visible code directly disprove the finding? (hardcoded safe literal, code never reaches sink, visible upstream sanitization). If `DISPROVEN: YES`, the finding is immediately downgraded to `FALSE_POSITIVE` with `AdversarialVerdict: FALSIFIED`.

2. **Full adversarial verify** - if the falsification filter doesn't disprove it, an agent loop (max 3 rounds) with repo tools traces data flow across files, hunts for auth gates, framework protections, or test-only paths. Returns:
   - `CONFIRMED` - an external entry point can reach the sink with real impact (finding stays `TRUE_POSITIVE`)
   - `DISPUTED` - no reachable exploit path or visible defenses neutralize it (downgraded to `FALSE_POSITIVE`)

When a finding is downgraded, the verdict flips to `FALSE_POSITIVE` with `HIGH` confidence and the adversarial reason replaces the verdict reason. The table output shows `adversarial confirmed`, `adversarial disputed`, or `adversarial falsified` next to the verdict.

Use:

```bash
broly scan . --sast --ai-triage --adversarial
```

### Exploit Chains

`--exploit-chains` synthesizes multi-step attack narratives by linking 2-4 cross-scanner true positives. It requires `--ai-triage` (it builds on triage verdicts).

Eligibility: at least 2 high-confidence `TRUE_POSITIVE` findings (or adversarial-confirmed) from **different scanner types** - SAST plus SCA, Secrets, Container, or Workflow. Known malicious packages are always eligible.

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

### Vulnerability Class Focus

`--<class>` flags focus the scan on specific vulnerability classes - useful for showcasing detection capability or hunting one bug class at a time:

```bash
broly scan . --sast --ai-triage --idor
broly scan . --sast --ai-triage --xss
broly scan . --sqli --rce --ssrf                    # combine classes
```

When a class is selected:

- The SAST prompt gets a **focus section** telling the model to hunt only those classes, with per-class guidance (e.g. for IDOR: trace whether an ownership check exists between the user-supplied identifier and the data access - its absence IS the vulnerability)
- Final findings from **all scanners** are filtered to the selected classes - matched by CWE ID first, then by keyword against rule ID/name/title/description/tags (whole-word matching, so `--rce` does not match "source")
- An info blurb prints at scan start describing each selected class and how Broly detects it

| Flag | Class | CWEs |
|------|-------|------|
| `--idor` | IDOR - Insecure Direct Object Reference | CWE-639, CWE-862, CWE-863 |
| `--bola` | BOLA - Broken Object Level Authorization | CWE-639, CWE-862, CWE-863 |
| `--sqli` | SQL Injection | CWE-89 |
| `--xss` | Cross-Site Scripting | CWE-79, CWE-80 |
| `--rce` | Remote Code / Command Execution | CWE-78, CWE-94, CWE-77, CWE-95 |
| `--ssrf` | Server-Side Request Forgery | CWE-918 |
| `--xxe` | XML External Entity Injection | CWE-611 |
| `--path-traversal` | Path Traversal | CWE-22, CWE-23, CWE-73 |
| `--deserialization` | Insecure Deserialization | CWE-502 |
| `--open-redirect` | Open Redirect | CWE-601 |
| `--weak-crypto` | Weak Cryptography | CWE-327, CWE-328, CWE-330, CWE-321 |
| `--hardcoded-secret` | Hardcoded Secrets | CWE-798, CWE-321, CWE-259 |

Also settable in `.broly.yaml` (CLI flags override):

```yaml
vuln_classes:
  - idor
  - xss
```

### Workflow Scanning

`--workflow` scans GitHub Actions workflows (`.github/workflows/*.yml`) and composite action manifests (`action.yml`/`action.yaml`) using [zizmor](https://docs.zizmor.sh/). If zizmor is not installed, Broly auto-installs it into `~/.cache/broly/venv/`:

```bash
broly scan . --workflow
broly scan . --workflow --ai-triage       # with AI verdict + fix
```

Findings include severity, snippet, and rule-specific remediation suggestions. Rule IDs are prefixed with `zizmor.` (e.g., `zizmor.unpinned-uses`, `zizmor.template-injection`).

### IaC Scanning

`--iac` scans infrastructure-as-code files using [checkov](https://www.checkov.io/). Supports Terraform, Kubernetes, Helm, and CloudFormation. If checkov is not installed, Broly auto-installs it into `~/.cache/broly/venv/`:

```bash
broly scan . --iac
broly scan . --iac --ai-triage          # with AI verdict + fix
```

Findings include severity (mapped from AWS Security Hub / CIS risk levels), code snippet, resource name, and rule-specific remediation. Rule IDs are prefixed with `broly.iac.` (e.g., `broly.iac.CKV_AWS_20`).

### Supply Chain Audit

`--supply-chain` audits dependencies against known-malicious package feeds using [depx](https://github.com/projectdiscovery/depx). Requires the `depx` binary:

```bash
# install depx (see https://github.com/projectdiscovery/depx)
```

```bash
broly scan . --supply-chain
```

Malicious-package findings are always `CRITICAL` severity and never baseline-suppressible. Rule IDs are prefixed with `sca.malicious.` (e.g., `sca.malicious.known_bad_package`, `sca.malicious.typosquat`). References link to the OpenSSF malicious-packages advisory when available.

---

## CI Integration

Run the **`broly` CLI** in GitHub Actions with the reusable workflow:

```yaml
jobs:
  security:
    uses: Shasheen8/Broly/.github/workflows/broly-scan.yml@main
    secrets:
      ai_api_key: ${{ secrets.AI_API_KEY }}
    with:
      ai_triage: true
      workflow: true
      iac: true
```

Inputs: `min_severity`, `scanners` (`all` | `sast` | `sca` | `secrets`), `ai_triage`, `workflow`, and `iac`. On pull requests it runs **secrets + SCA** on the full tree (and **pulls base images** referenced in Dockerfiles/Compose, same as local `broly scan`), runs **SAST** on changed code files only when `ai_api_key` is set, uploads SARIF to the GitHub Security tab, and posts a **summary PR comment** (findings table only - no fix blocks or false-positive checkboxes). Push/workflow_dispatch runs a full-repo scan with the same scanner selection rules.

### Optional: `broly-app` (local GitHub App)

`cmd/broly-app` is a webhook server for testing the **full PR experience** locally. It runs the same pipeline as the CLI - agentic SAST triage, adversarial verification, exploit chains, workflow/IaC scanning, and supply-chain audit - all against a local clone.

On each pull request it:

- Clones the PR head and runs **secrets + SCA + workflow + IaC** on the repo (auto-detected based on tool availability)
- Runs **SAST** on changed code files only when `TOGETHER_API_KEY` is set
- Emits a **base-image advisory** for each changed Dockerfile/Compose `FROM` (compared against the base branch so unchanged images don't re-alert) instead of pulling images - SCA already covers language packages
- **Scopes findings to the PR diff at line level**: SAST/secrets/IaC/workflow findings must land on a line the PR added or modified (parsed from GitHub's per-file patches); SCA/container findings match at file level, with file-level fallback when no patch is available
- Runs **AI triage + adversarial verification** after diff scoping, so LLM budget is only spent on findings the PR actually introduced
- Synthesizes **exploit chains** linking cross-scanner true positives
- Runs **supply-chain audit** when `depx` is available
- Posts a **check run** (summary + file annotations) and a **PR comment** (severity table, triage verdicts, adversarial status, collapsible fix suggestions, exploit chains, dismissed false positives, false-positive checkboxes)

Push events run the same pipeline against the pushed commit (commit patches provide the same line-level scoping) and post a **check run** on the commit - no PR comment.

Stage budgets: scan 10m, triage 15m, adversarial 10m, exploit chains 5m.

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

enable_workflow: false                              # optional: scan GitHub Actions workflows with zizmor
enable_iac: false                                   # optional: scan IaC files with checkov
supply_chain: false                                 # optional: audit deps against malicious-package feeds
vuln_classes: []                                    # optional: focus scan on vuln classes (idor, xss, sqli, ...)

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
