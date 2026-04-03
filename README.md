<table>
<tr>
<td width="300">
<img src="assets/broly-logo.png" alt="Broly" width="280"/>
</td>
<td>

# Broly

### A berserker code security scanner.

Secrets · SCA · SAST · Containers in a single binary.
AI-powered. No rule files. No rule engine.

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
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 20 ecosystems | `--ai-sca-reachability` checks if the vuln is actually called |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3-Coder-Next-FP8` + regex pre-filter | Source-to-sink data flow · 17 deterministic patterns · priority scoring |
| **Dockerfile** | AI-powered · Dockerfile, Containerfile, Compose | Privilege escalation, secret exposure, dangerous mounts |
| **Container** | [go-containerregistry](https://github.com/google/go-containerregistry) + [osv.dev](https://osv.dev) · Alpine, Debian, Ubuntu, RHEL | OS package CVEs with layer attribution |
| **License** | File-based detection · 13 license types | Policy engine: `allowed_licenses` / `denied_licenses` in `.broly.yaml` |
| **SBOM** | [osv-scalibr](https://github.com/google/osv-scalibr) · 20 ecosystems | `broly sbom` generates CycloneDX 1.5 or SPDX 2.3 with PURLs |

---

## Install

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
```

Pre-built Linux binaries on [Releases](https://github.com/Shasheen8/Broly/releases). macOS: build from source with `brew install vectorscan && make build` for Hyperscan support.

SAST and AI features are powered by [Together AI](https://together.ai) and require an API key:

```bash
export TOGETHER_API_KEY=your_key_here
```

---

## Usage

```bash
broly scan                                         # all scanners, current directory
broly scan /path/to/project                        # specific path


# Individual Scanners
broly scan --secrets                               # secrets only
broly scan --sca                                   # SCA only
broly scan --sast                                  # SAST only (requires TOGETHER_API_KEY)


# AI Enhancements
broly scan --ai-filter-secrets                     # filter secrets false positives with AI
broly scan --ai-sca-reachability                   # check if vulnerable deps are actually called
broly scan --ai-triage                             # verdict (TP/FP) + fix suggestion per finding
broly scan --ai-triage --explain                   # + concise attack-scenario sentence per finding


# Container Scanning
broly scan --container alpine:3.19                 # scan a container image for vulnerabilities
broly scan --container ./image.tar                 # scan from tarball


# Output
broly scan -f json                                 # JSON output
broly scan -f sarif -o results.sarif               # SARIF 2.1.0 for GitHub Code Scanning
broly scan --min-severity high                     # only high and critical


# SBOM Generation
broly sbom                                         # CycloneDX 1.5 to stdout
broly sbom -f spdx -o sbom.spdx.json              # SPDX 2.3 to file


# Config
broly scan --config .broly.yaml                    # load project config file
broly scan --baseline .broly-baseline.yaml         # suppress known FPs / require specific findings
broly scan --incremental                           # skip unchanged files (uses .broly-cache.json)
```

---

## Scanner Output

### SAST

A fast regex pre-filter catches 18 known vulnerability patterns instantly (SQL injection, hardcoded secrets, XSS sinks, weak crypto, etc.). Then the LLM traces data flow from source to sink and finds what static rules miss.

```
  ▸ SAST (4 findings)

  SEVERITY     ISSUE                            FILE                      DESCRIPTION
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  CRITICAL     SQL injection via unsanitize..   api/handlers.py:10        User input flows directly ..
  CRITICAL     OS command injection via uns..   api/handlers.py:15        OS command injection via u..
  HIGH         Path traversal in read_file      api/handlers.py:20        Path traversal in read_fil..
  HIGH         Insecure deserialization via..   api/handlers.py:25        Insecure deserialization v..
```

### Dockerfile and Compose

Auto-detected during normal scans. Specialized prompts cover privilege escalation, hardcoded secrets, dangerous mounts, unpinned base images, and more.

```
  ▸ DOCKERFILE (4 findings)

  SEVERITY     ISSUE                            FILE                                DESCRIPTION
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  CRITICAL     Hardcoded secrets in ENV/ARG     Dockerfile:3                        Secrets visible in image hi..
  CRITICAL     Docker socket mounted            docker-compose.yml:14               Full control over Docker da..
  HIGH         curl piped to bash               Dockerfile:10                       Compromised script runs as ..
  MEDIUM       Running as root (no USER)        Dockerfile:1                        Increases blast radius of a..
```

### Secrets

487 rules. `--ai-filter-secrets` reads surrounding code context and eliminates placeholders and test values:

```
  ▸ SECRETS (3 findings)

  SEVERITY     RULE                             FILE                      REDACTED
  ──────────────────────────────────────────────────────────────────────────────────
  HIGH         AWS API Key                      config/example.py:6       AKIA****MPLE
  HIGH         AWS API Credentials              config/example.py:6       AKIA****KEY"
  HIGH         GitHub Personal Access Token     config/example.py:9       ghp_****8B4a
```

### SCA

19 ecosystems, 50+ lockfile formats. `--ai-sca-reachability` checks if the vulnerable function is actually called:

```
  ▸ SCA (3 findings)

  SEVERITY     VULN ID                PACKAGE            VERSION        FIXED            ECOSYSTEM
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  MEDIUM       GHSA-9hjg-9r4m-mvj7    requests           2.31.0         no patch         PyPI
  MEDIUM       GHSA-496j-2rq6-j6cc    grpcio             1.54.0         no patch         PyPI
  MEDIUM       GHSA-cfgp-2977-2fmm    grpcio             1.54.0         no patch         PyPI
```

### Container

`--container` pulls an image, extracts OS packages, and matches against OSV. Each finding shows which layer introduced it:

```
  ▸ CONTAINER (5 findings)

  SEVERITY     VULN ID                PACKAGE            VERSION        FIXED            ECOSYSTEM          LAYER
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  MEDIUM       ALPINE-CVE-2023-42..   busybox            1.36.1-r2      no patch         Alpine:v3.18       #1
  MEDIUM       ALPINE-CVE-2025-26..   musl               1.2.4-r1       no patch         Alpine:v3.18       #1
```

### AI Triage

`--ai-triage` labels each finding TRUE/FALSE positive with a confidence score and a fix. For container/SCA findings with no patch, it suggests mitigations. `--explain` adds a one-sentence attack scenario:

```
  CRITICAL     SQL injection via unsanitize..   api/handlers.py:10        User input flows directly ..
  🔺 TRUE_POSITIVE [HIGH]  User input flows directly into raw SQL query without parameterization
      An attacker sends id=1 OR 1=1 to dump the entire users table.
    fix:
      query = "SELECT * FROM users WHERE id = %s"
      cursor.execute(query, (user_id,))

  HIGH         Path traversal in read_file      api/handlers.py:20        Path traversal in read_fil..
  🟢 FALSE_POSITIVE [HIGH]  File path is validated against an allowlist before use
```

---

## Developer Feedback Loop

Check a box in the PR comment to mark a finding as a false positive. Broly verifies write access, commits the fingerprint to `.broly-baseline.yaml`, and the finding never surfaces again.

```
- [ ] 🔴 CRITICAL · SQL injection in get_user() · api/handlers.py:7
```

Suppressions accumulate over time; each repo builds its own false positive memory.

---

## GitHub App

Install once, scans every PR automatically. No per-repo workflow setup.

The app clones the repo at the PR head, runs Broly with AI triage, and posts findings as a check run + PR comment. Only findings in changed files are reported — no historic noise.

```bash
# run the app server locally
APP_ID=123456 PRIVATE_KEY_PATH=./app.pem WEBHOOK_SECRET=your_secret go run ./cmd/broly-app
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
> `suppress` silences known false positives. `require` asserts specific findings must be detected every scan; missing entries cause a non-zero exit.

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

## Acknowledgments

| Project | Role |
|---------|------|
| [Titus](https://github.com/praetorian-inc/titus) | Secrets engine: 487 rules, Hyperscan + Go regex |
| [osv-scalibr](https://github.com/google/osv-scalibr) | Lockfile extraction across 50+ formats |
| [osv.dev](https://osv.dev) | Vulnerability database by Google |
| [go-containerregistry](https://github.com/google/go-containerregistry) | Container image pulling and layer inspection |
| [go-github](https://github.com/google/go-github) + [ghinstallation](https://github.com/bradleyfalzon/ghinstallation) | GitHub App authentication and API |
| [Together AI](https://together.ai) | AI inference for SAST, triage, and reachability |

---

## License

MIT. See [LICENSE](LICENSE) for the full text.
