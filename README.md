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
| **Secrets** | [Titus](https://github.com/praetorian-inc/titus) · 487 rules · Hyperscan | `--ai-filter-secrets` eliminates false positives |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 20 ecosystems | `--ai-sca-reachability` · `--package-intelligence` for hallucinated deps |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3.5-9B` · 17 regex patterns | Slice-aware multi-file · source-to-sink data flow · priority scoring |
| **Dockerfile** | AI-powered · Dockerfile, Containerfile, Compose | Privilege escalation · secret exposure · dangerous mounts |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + [osv.dev](https://osv.dev) · pulls registry/local/tar images | OS package CVEs with layer attribution · auto-discovers `FROM` images in Dockerfiles and Compose |
| **License** | File-based detection · 13 license types | Policy engine via `allowed_licenses` / `denied_licenses` in `.broly.yaml` |
| **SBOM** | [osv-scalibr](https://github.com/google/osv-scalibr) · 20 ecosystems | CycloneDX 1.5 or SPDX 2.3 with PURLs |

---

## Install

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
```

Requires [Vectorscan](https://github.com/VectorCamp/vectorscan) for the secrets engine:

```bash
brew install vectorscan                   # macOS
sudo apt-get install -y libhyperscan-dev  # Ubuntu / Debian
```

Or download a pre-built binary (no dependencies) from [Releases](https://github.com/Shasheen8/Broly/releases).

SAST and AI features require a [Together AI](https://together.ai) API key:

```bash
export TOGETHER_API_KEY=your_key_here
```

---

## Usage

```bash
broly scan                                        # all scanners, current directory
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

# Container scanning (pulls and analyzes the image — not advisory-only)
broly scan --container alpine:3.19                # pull and scan a registry image
broly scan --container ./image.tar                # scan from a local tarball
broly scan .                                      # also scans base images referenced in Dockerfile / Compose files under targets

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
> **GitHub Actions (workflow) scanning** is not part of this CLI-focused repo. Setting `enable_workflow: true` in `.broly.yaml` makes `broly scan` exit with an error. Use the reusable workflow below or a hosted scanner if you need Actions coverage.

---

## Scanner Output

*Video for each scanner output coming soon.*

Each scanner outputs an aligned table in the terminal. Supports JSON (`-f json`), SARIF (`-f sarif`), and table (default).

### AI Triage

`--ai-triage` adds an AI verdict to each finding in the terminal table:

- `TRUE_POSITIVE` or `FALSE_POSITIVE`
- confidence score
- short reasoning in the `ASSESSMENT / CONTEXT` column
- targeted remediation in the `TARGETED FIX` column, including a concrete code fix when the model has enough local context

`--ai-triage --explain` adds one more thing: a plain-language attack scenario or impact sentence. The table format stays the same, but each finding becomes more verbose.

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

Supports `min_severity`, `scanners`, and `ai_triage` inputs. Uploads SARIF to the GitHub Security tab when configured in the workflow.

### Optional: `broly-app` webhook server

`cmd/broly-app` is a minimal GitHub App webhook handler for local experiments (PR scan + check run). It does **not** include the production hosted control plane (DynamoDB, baseline registry, workflow/zizmor, org-wide PR bot). For that, use Together’s deployed Broly or extend this repo yourself.

```bash
APP_ID=... PRIVATE_KEY_PATH=./broly.pem WEBHOOK_SECRET=... TOGETHER_API_KEY=... \
  go run ./cmd/broly-app
```

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
path_strip_prefix: /home/runner/work/myrepo/myrepo   # optional: normalize paths in CI output
additional_suppressions:                            # optional: extra fingerprint suppressions
  - "abc123..."

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
