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

<a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
<a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
<a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/badge/Release-latest-blue?style=flat" alt="Release"></a>
<a href="https://together.ai"><img src="https://img.shields.io/badge/Powered%20by-Together%20AI-blueviolet?style=flat" alt="Together AI"></a>

</td>
</tr>
</table>

---

## What It Does

Broly runs three security scanners in parallel on your codebase and delivers results in seconds:

| Scanner | Engine | AI Layer |
|---------|--------|----------|
| **Secrets** | [Titus](https://github.com/praetorian-inc/titus) · 487 rules · Hyperscan | `--ai-filter-secrets` eliminates false positives |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 19 ecosystems | `--ai-sca-reachability` checks if the vuln is actually called |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3-Coder-Next-FP8` | Always-on · source-to-sink data flow · CVSS scoring |
| **Dockerfile** | AI-powered · Dockerfile, Containerfile, Compose | Privilege escalation, secret exposure, dangerous mounts |

---

## Install

**Go install** (any platform):

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
```

**Linux** - pre-built binary from [Releases](https://github.com/Shasheen8/Broly/releases).

**macOS** - build from source with Hyperscan (faster secrets scanning):

```bash
brew install vectorscan
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build
```

> [!TIP]
> `go install` uses pure Go regex for secrets. The source build enables Hyperscan via `-tags vectorscan` for significantly faster pattern matching on large codebases.

**SAST / AI features** require a Together AI key:

```bash
export TOGETHER_API_KEY=your_key_here
```

---

## Usage

```bash
broly scan                                         # all scanners, current directory
broly scan /path/to/project                        # specific path

# individual scanners
broly scan --secrets                               # secrets only
broly scan --sca                                   # SCA only
broly scan --sast                                  # SAST only (requires TOGETHER_API_KEY)


# AI enhancements
broly scan --ai-filter-secrets                     # filter secrets false positives with AI
broly scan --ai-sca-reachability                   # check if vulnerable deps are actually called
broly scan --ai-triage                             # verdict (TP/FP) + fix suggestion per finding
broly scan --ai-triage --explain                   # + concise attack-scenario sentence per finding
broly scan --ai-model Qwen/Qwen3-Coder-Next-FP8    # override model (default)


# output
broly scan -f json                                 # JSON output
broly scan -f sarif -o results.sarif               # SARIF 2.1.0 for GitHub Code Scanning
broly scan --min-severity high                     # only high and critical
broly scan --quiet                                 # suppress progress output


# container scanning
broly scan --container alpine:3.19                 # scan a container image for vulnerabilities
broly scan --container ./image.tar                 # scan from tarball


# config
broly scan --config .broly.yaml                    # load project config file
broly scan --baseline .broly-baseline.yaml         # suppress known FPs / require specific findings
broly scan --incremental                           # skip unchanged files (uses .broly-cache.json)
broly scan --sca --offline                         # skip OSV API lookup
```

---

## Scanner Output

### SAST

Each file is sent to `Qwen/Qwen3-Coder-Next-FP8` with a structured security prompt. The model traces data flow from source to sink, infers CVSS scores, and finds what static rules miss.

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

Dockerfiles, Containerfiles, and Compose files are auto-detected and scanned with specialized security prompts. Covers privilege escalation, hardcoded secrets, dangerous mounts, unpinned base images, curl-pipe-bash, and more.

```
  ▸ SAST (18 findings)

  SEVERITY     ISSUE                            FILE                                DESCRIPTION
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  CRITICAL     Hardcoded secrets (DB_PASSWO..   Dockerfile:0                        An attacker with access to t..
  CRITICAL     Container is running in priv..   docker-compose.yml:0                An attacker who compromises ..
  CRITICAL     Docker socket mounted            docker-compose.yml:0                Full control over Docker dae..
  HIGH         ADD from remote URL              Dockerfile:9                        MITM or compromised source c..
  HIGH         curl piped to bash               Dockerfile:10                       Compromised script runs as r..
  MEDIUM       Running as root (no USER)        Dockerfile:0                        Increases blast radius of an..
  MEDIUM       Unpinned base image :latest      Dockerfile:1                        May pull a changed or compro..
  ...
```

### Secrets

487 rules covering AWS, GCP, Azure, GitHub, OpenAI, Anthropic, Slack, Stripe, SSH/PGP keys, database URIs, JWTs, and more.

`--ai-filter-secrets` reads surrounding code context and filters out placeholders, test values, and examples:

```
  ▸ SECRETS (3 findings)

  SEVERITY     RULE                             FILE                      REDACTED
  ──────────────────────────────────────────────────────────────────────────────────
  HIGH         AWS API Key                      config/example.py:6       AKIA****MPLE
  HIGH         AWS API Credentials              config/example.py:6       AKIA****KEY"
  HIGH         GitHub Personal Access Token     config/example.py:9       ghp_****8B4a
```

With `--ai-filter-secrets`: `✔ No findings detected. Clean scan!`

### SCA

19 ecosystems (Go, Python, JS, Ruby, Rust, Java, PHP, .NET, Dart, C/C++, and more), 50+ lockfile formats.

```
  ▸ SCA (13 findings)

  SEVERITY     VULN ID                PACKAGE            VERSION        FIXED            ECOSYSTEM
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  MEDIUM       GHSA-9hjg-9r4m-mvj7    requests           2.31.0         no fix           PyPI
  MEDIUM       GHSA-496j-2rq6-j6cc    grpcio             1.54.0         no fix           PyPI
  MEDIUM       GHSA-cfgp-2977-2fmm    grpcio             1.54.0         no fix           PyPI
  ...
```

`--ai-sca-reachability` checks whether the vulnerable functions are actually called. Unreachable findings are downgraded one severity level and tagged `[Unreachable]`.

### AI Triage

`--ai-triage` labels each finding TRUE/FALSE positive with a confidence score and a fix. `--explain` adds a one-sentence attack scenario:

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

## Configuration

### Config file

> [!TIP]
> `.broly.yaml` is loaded automatically from the repo root. CLI flags always override it. See [`.broly.yaml`](.broly.yaml) for a working example.

```yaml
min_severity: low
exclude_paths:
  - vendor
  - .git
workers: 8
```

### Baseline

> [!NOTE]
> `suppress` silences known false positives. `require` asserts specific findings must be detected every scan; missing entries cause a non-zero exit. See [`.broly-baseline.yaml`](.broly-baseline.yaml) for a working example.

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

Broly stands on the shoulders of some excellent open-source projects:

| Project | Role |
|---------|------|
| [Titus](https://github.com/praetorian-inc/titus) | Secrets engine: 487 rules, Hyperscan + Go regex |
| [osv-scalibr](https://github.com/google/osv-scalibr) | Lockfile extraction across 50+ formats |
| [osv.dev](https://osv.dev) | Vulnerability database by Google |
| [Together AI](https://together.ai) | AI inference for SAST, triage, and reachability |

---

## License

MIT. See [LICENSE](LICENSE) for the full text.
