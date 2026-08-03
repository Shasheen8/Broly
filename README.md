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

## Scanners

| Scanner | Engine | Flag |
|---------|--------|------|
| **Secrets** | [Titus](https://github.com/praetorian-inc/titus) · 487 rules · Hyperscan | `--secrets` (default on) |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 20 ecosystems | `--sca` (default on) |
| **SAST** | [Together AI](https://together.ai) · 17 regex prefilter + LLM analysis | `--sast` (default on, needs `TOGETHER_API_KEY`) |
| **Workflow** | [zizmor](https://docs.zizmor.sh/) · GitHub Actions | `--workflow` (auto-installs) |
| **IaC** | [checkov](https://www.checkov.io/) · Terraform, K8s, Helm, CloudFormation | `--iac` (auto-installs) |
| **Supply Chain** | [depx](https://github.com/projectdiscovery/depx) · malicious-package audit | `--supply-chain` |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + osv.dev | `--container <image>` or `--auto-containers` |
| **SBOM** | osv-scalibr · CycloneDX 1.5 or SPDX 2.3 | `broly sbom` |

---

## Install

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
export TOGETHER_API_KEY=your_key_here    # required for SAST + AI features
```

Or download from [Releases](https://github.com/Shasheen8/Broly/releases). For faster secrets scanning, install [Vectorscan](https://github.com/VectorCamp/vectorscan) (`brew install vectorscan`).

---

## Usage

```bash
broly scan                              # secrets + SCA + SAST
broly scan . --workflow --iac           # IaC + workflow (auto-installs zizmor/checkov)
broly scan . --supply-chain             # malicious package audit
broly scan . --container alpine:3.19    # scan a container image

# AI features (require TOGETHER_API_KEY)
broly scan . --ai-triage                # TP/FP verdict + fix per finding
broly scan . --ai-triage --adversarial  # adversarial verify on critical SAST TPs
broly scan . --ai-triage --exploit-chains  # link cross-scanner TPs into attack narratives
broly scan . --sqli --xss --rce         # focus on specific vuln classes

# Output
broly scan -f sarif -o results.sarif    # SARIF for GitHub Security tab
broly scan -f json                      # JSON
broly scan --min-severity high          # only high + critical

broly sbom -f cyclonedx -o sbom.json    # generate SBOM
broly update                            # update to latest version
```

> [!NOTE]
> zizmor and checkov auto-install into `~/.cache/broly/venv/` on first use. depx must be installed manually: `go install github.com/projectdiscovery/depx/v2/cmd/depx@latest`

---

## AI Features

**AI Triage** (`--ai-triage`) adds a TRUE_POSITIVE / FALSE_POSITIVE verdict, confidence, reasoning, and a targeted code fix for SAST, SCA, IaC, and Workflow findings. Add `--explain` for a plain-language attack scenario per finding.

**Adversarial Verification** (`--adversarial`) runs a second AI pass on critical SAST true positives — an agent traces data flow across files to confirm or falsify reachability. Returns `CONFIRMED`, `DISPUTED`, or `FALSIFIED`.

**Exploit Chains** (`--exploit-chains`) links 2-4 cross-scanner true positives into multi-step attack narratives.

**Agentic Triage** activates automatically for high-severity SAST findings when scanning a local directory — the AI can read related files and search the repo before deciding a verdict.

### Vulnerability Class Focus

`--<class>` flags narrow the scan to specific bug classes:

| Flag | Class | CWEs |
|------|-------|------|
| `--sqli` | SQL Injection | CWE-89 |
| `--xss` | Cross-Site Scripting | CWE-79, CWE-80 |
| `--rce` | Remote Code / Command Execution | CWE-78, CWE-94, CWE-77, CWE-95 |
| `--ssrf` | Server-Side Request Forgery | CWE-918 |
| `--xxe` | XML External Entity | CWE-611 |
| `--idor` | IDOR | CWE-639, CWE-862, CWE-863 |
| `--bola` | BOLA | CWE-639, CWE-862, CWE-863 |
| `--path-traversal` | Path Traversal | CWE-22, CWE-23, CWE-73 |
| `--deserialization` | Insecure Deserialization | CWE-502 |
| `--open-redirect` | Open Redirect | CWE-601 |
| `--weak-crypto` | Weak Cryptography | CWE-327, CWE-328, CWE-330, CWE-321 |
| `--hardcoded-secret` | Hardcoded Secrets | CWE-798, CWE-321, CWE-259 |

```bash
broly scan . --sast --ai-triage --sqli    # SQL injection only
broly scan . --sqli --rce --ssrf          # combine classes
```

---

## CI Integration

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

Uploads SARIF to the GitHub Security tab and posts a summary PR comment.

### `broly-app` (local GitHub App)

Webhook server for the full PR experience locally — clones, scans, triages, and posts check runs + PR comments. Uses the same pipeline as the CLI.

```bash
# terminal 1: smee proxy
npx smee-client --url https://smee.io/your-channel --target http://localhost:8080/webhook

# terminal 2: broly-app
APP_ID=... PRIVATE_KEY_PATH=./broly.pem WEBHOOK_SECRET=... TOGETHER_API_KEY=... \
  go run ./cmd/broly-app
```

Create a channel at [smee.io](https://smee.io), set the webhook URL in your GitHub App settings, and you're ready to scan PRs locally.

---

## Configuration

`.broly.yaml` is loaded automatically from the repo root. CLI flags override.

```yaml
min_severity: low
exclude_paths: [vendor, .git]
workers: 8
enable_workflow: true
enable_iac: true
supply_chain: true
vuln_classes: [sqli, xss]

allowed_licenses: [MIT, Apache-2.0]    # license policy (optional)
denied_licenses: [GPL-3.0]
```

### Baseline (suppress / require)

```yaml
suppress:
  - fingerprint: "abc123..."
    reason: "test fixture"

require:
  - rule_id: "SQL-INJECTION"
    file: "api/handlers.py"
```

### Inline suppression

```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # broly:ignore
```

---

## License

MIT. See [LICENSE](LICENSE).