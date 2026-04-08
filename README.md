<table>
<tr>
<td width="300">
<img src="assets/broly-logo.png" alt="Broly" width="280"/>
</td>
<td align="center">

# Broly

### A berserker code security scanner.

Secrets · SCA · SAST · Containers in a single binary.
AI-powered. No rule files. No rule engine.

<a href="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml"><img src="https://github.com/Shasheen8/Broly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat&logo=go" alt="Go"></a>
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
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 20 ecosystems | `--ai-sca-reachability` checks if the vuln is actually called · `--package-intelligence` detects hallucinated/non-existent dependencies |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3-Coder-Next-FP8` + regex pre-filter | Slice-aware multi-file analysis · source-to-sink data flow · 17 deterministic patterns · priority scoring |
| **Dockerfile** | AI-powered · Dockerfile, Containerfile, Compose | Privilege escalation, secret exposure, dangerous mounts |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + [osv.dev](https://osv.dev) · Alpine, Debian, Ubuntu, RHEL | OS package CVEs with layer attribution |
| **License** | File-based detection · 13 license types | Policy engine: `allowed_licenses` / `denied_licenses` in `.broly.yaml` |
| **SBOM** | [osv-scalibr](https://github.com/google/osv-scalibr) · 20 ecosystems | `broly sbom` generates CycloneDX 1.5 or SPDX 2.3 with PURLs |

---

## Install

**Go install:**

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
```

**Pre-built binaries** (Linux/macOS): [Releases](https://github.com/Shasheen8/Broly/releases).

**From source** (full Hyperscan support for secrets engine):

```bash
brew install vectorscan   # macOS
make build
```

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

# Container scanning
broly scan --container alpine:3.19                # pull and scan a registry image
broly scan --container ./image.tar                # scan from a local tarball

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
broly scan --incremental                          # skip unchanged files
```

---

## Scanner Output

*Demo videos coming soon.*

Each scanner outputs an aligned table in the terminal. Supports JSON (`-f json`), SARIF (`-f sarif`), and table (default).

### AI Triage

`--ai-triage` labels every finding TRUE or FALSE positive with a confidence score and a concrete fix. Add `--explain` for a one-sentence attack scenario:

```
  CRITICAL   SQL injection via unsanitized user input         api/handlers.py:10
  🔺 TRUE_POSITIVE  confidence: HIGH
     An attacker can send id=1 OR 1=1-- to dump the entire users table.
     fix:
       cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

  HIGH       Path traversal in read_file                      api/handlers.py:20
  🟢 FALSE_POSITIVE  confidence: HIGH
     File path is validated against an allowlist before reaching the filesystem.
```

---

## CI Integration

**GitHub App**: install once on your org and every PR gets scanned automatically. No per-repo setup needed.

**Reusable workflow**: drop one line into any repo's existing CI:

```yaml
jobs:
  security:
    uses: Shasheen8/Broly/.github/workflows/broly-scan.yml@main
    secrets:
      ai_api_key: ${{ secrets.AI_API_KEY }}
```

Supports `min_severity`, `scanners`, and `ai_triage` inputs. Posts findings as a PR comment and uploads SARIF to the GitHub Security tab.

## GitHub App

One install covers your entire org. Every PR gets scanned automatically. No workflow files, no per-repo setup, no secrets to configure per repo.

**On every PR, Broly:**
- Runs secrets, SCA, and SAST on changed files only (no historic noise)
- Posts findings as an inline check run with file:line annotations
- Labels each finding TRUE/FALSE positive with a confidence score and fix suggestion
- Adds a checkbox per finding. Check it to suppress it forever

> [!NOTE]
> Only findings in files changed by the PR are reported. Broly never flags pre-existing issues on a clean PR.

**Developer feedback loop:** when a developer checks a false positive box, Broly commits the fingerprint to `.broly-baseline.yaml` on the branch. The finding is suppressed on every future scan, automatically. No config needed. Each repo builds its own false positive memory over time.

### Running locally

```bash
APP_ID=your_app_id \
PRIVATE_KEY_PATH=./broly.pem \
WEBHOOK_SECRET=your_webhook_secret \
TOGETHER_API_KEY=your_key \
go run ./cmd/broly-app
```

> [!TIP]
> Use [smee.io](https://smee.io) to proxy GitHub webhooks to your local server during development.

### Deployment

Multi-stage Dockerfile at `cmd/broly-app/Dockerfile`. Chainguard hardened runtime. Non-root, no shell, minimal attack surface.

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `APP_ID` | ✓ | GitHub App ID |
| `PRIVATE_KEY_PATH` | ✓ | Path to the `.pem` private key file |
| `WEBHOOK_SECRET` | ✓ | Webhook secret from the GitHub App settings |
| `TOGETHER_API_KEY` | ✓ | Together AI key — required for SAST and AI triage |
| `PORT` | — | HTTP port (default: `8080`) |
| `MAX_CONCURRENT_SCANS` | — | Parallel scan limit (default: `4`) |

```bash
docker build -f cmd/broly-app/Dockerfile -t broly-app .

docker run -p 8080:8080 \
  -e APP_ID=your_app_id \
  -e PRIVATE_KEY_PATH=/secrets/broly.pem \
  -e WEBHOOK_SECRET=your_webhook_secret \
  -e TOGETHER_API_KEY=your_key \
  -v /path/to/broly.pem:/secrets/broly.pem:ro \
  broly-app
```

> [!TIP]
> In production, mount the private key from a secrets manager rather than the host filesystem. The `/healthz` endpoint is available for uptime monitoring.

> [!WARNING]
> Never commit the `.pem` private key to source control. Add it to `.gitignore`.

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

MIT. See [LICENSE](LICENSE) for the full text.
