<p align="center">
  <img src="assets/broly-logo.png" alt="Broly" width="350"/>
</p>

<h1 align="center">Broly</h1>
<h3 align="center">A berserker vulnerability scanner.</h3>

<p align="center">Secrets · SCA · SAST — powered by AI, shipped as a single binary.</p>

<p align="center">
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
  <a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/github/v/release/Shasheen8/Broly?style=flat&label=Release" alt="Release"></a>
  <a href="https://together.ai"><img src="https://img.shields.io/badge/Powered%20by-Together%20AI-blueviolet?style=flat" alt="Together AI"></a>
</p>

---

## What It Does

Broly runs three security scanners in parallel on your codebase and delivers results in seconds:

| Scanner | Engine | AI Layer |
|---------|--------|----------|
| **Secrets** | [Titus](https://github.com/praetorian-inc/titus) · 487 rules · Hyperscan | `--ai-filter-secrets` — eliminates false positives |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) · 19 ecosystems | `--ai-sca-reachability` — checks if the vuln is actually called |
| **SAST** | [Together AI](https://together.ai) · `Qwen/Qwen3-Coder-Next-FP8` | Always-on · data flow analysis · CVSS scoring |

---

## Install

**Linux** — download a pre-built binary from [Releases](https://github.com/Shasheen8/Broly/releases).

**macOS** — build from source:

```bash
brew install vectorscan
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build
```

**SAST / AI features** require a Together AI key:

```bash
export TOGETHER_API_KEY=your_key_here
```

---

## Usage

```bash
broly scan                              # run all scanners on current directory
broly scan /path/to/project             # specific path

# individual scanners
broly scan --secrets                    # secrets only
broly scan --sca                        # SCA only
broly scan --sast                       # SAST only (requires TOGETHER_API_KEY)

# AI enhancements
broly scan --ai-filter-secrets          # filter secrets false positives with AI
broly scan --ai-sca-reachability        # check if vulnerable deps are actually called
broly scan --ai-model Qwen/Qwen3-Coder-Next-FP8   # override model (default)

# output
broly scan -f json                      # JSON output
broly scan -f sarif -o results.sarif    # SARIF for GitHub Code Scanning
broly scan --min-severity high          # only high and critical
broly scan --sca --offline              # skip OSV API lookup
```

---

## Snapshots

### SAST — AI-powered code analysis

```
broly vdev — scanning api/handlers.py
scanners: sast | workers: 8

  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║    ⚡  BROLY  --  Berserker Vulnerability Scanner    ║
  ║    Secrets · SCA · SAST · Powered by Together AI     ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝

  ▸ SAST (4 findings)

  SEVERITY     ISSUE                            FILE                      DESCRIPTION
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  CRITICAL     SQL injection via unsanitize..   api/handlers.py:10        SQL injection via unsaniti..
  CRITICAL     OS command injection via uns..   api/handlers.py:15        OS command injection via u..
  HIGH         Path traversal in read_file      api/handlers.py:20        Path traversal in read_fil..
  HIGH         Insecure deserialization via..   api/handlers.py:25        Insecure deserialization v..

  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║  4  total findings                                   ║
  ║  Critical 2    High 2    Medium 0    Low 0           ║
  ║  duration: 9.592s                                    ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
```

The SAST engine sends each file to `Qwen/Qwen3-Coder-Next-FP8` with a structured security prompt that traces data flow from source to sink, infers CVSS scores, and pinpoints exact line numbers — no rule files required.

---

### Secrets — with AI false positive filtering

Without `--ai-filter-secrets` (raw regex hits):

```
  ▸ SECRETS (3 findings)

  SEVERITY     RULE                             FILE                      REDACTED
  ──────────────────────────────────────────────────────────────────────────────────
  HIGH         AWS API Key                      config/example.py:6       AKIA****MPLE
  HIGH         AWS API Credentials              config/example.py:6       AKIA****KEY"
  HIGH         GitHub Personal Access Token     config/example.py:9       ghp_****8B4a
```

With `--ai-filter-secrets` (AI reads surrounding context):

```
  ✔  No findings detected. Clean scan!
```

The AI recognized the file contained documented placeholder values (`EXAMPLE` in variable names, "Test / dummy values" comment) and filtered them all as false positives — reducing noise to zero.

---

### SCA — dependency vulnerability scan

```
broly vdev — scanning /path/to/project
scanners: sca | workers: 8

  ▸ SCA (13 findings)

  SEVERITY     VULN ID                PACKAGE            VERSION        FIXED            ECOSYSTEM
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  MEDIUM       GHSA-9hjg-9r4m-mvj7    requests           2.31.0         no fix           PyPI
  MEDIUM       GHSA-496j-2rq6-j6cc    grpcio             1.54.0         no fix           PyPI
  MEDIUM       GHSA-cfgp-2977-2fmm    grpcio             1.54.0         no fix           PyPI
  MEDIUM       GHSA-wh2j-26j7-9728    google-cloud-ai    1.25.0         no fix           PyPI
  MEDIUM       GHSA-7gcm-g887-7qv7    protobuf           3.20.3         no fix           PyPI
  ...

  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║  13  total findings                                  ║
  ║  Critical 0    High 0    Medium 13   Low 0           ║
  ║  duration: 388ms                                     ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
```

Add `--ai-sca-reachability` to check whether the vulnerable functions are actually called in your code. Unreachable findings are automatically downgraded one severity level and tagged `[Unreachable]`.

---

## AI Architecture

```
                        ┌─────────────────────────┐
                        │      broly scan          │
                        └────────────┬────────────┘
               ┌─────────────────────┼──────────────────────┐
               ▼                     ▼                       ▼
        ┌─────────────┐      ┌──────────────┐       ┌──────────────┐
        │   Secrets   │      │     SCA      │       │     SAST     │
        │   (Titus)   │      │ (osv-scalibr │       │  (Together   │
        │  487 rules  │      │  + osv.dev)  │       │     AI)      │
        └──────┬──────┘      └──────┬───────┘       └──────┬───────┘
               │                   │                       │
      --ai-filter-secrets  --ai-sca-reachability    Always-on AI
               │                   │                       │
               ▼                   ▼                       ▼
        AI reads context    AI finds importing      AI traces data flow
        filters FP hits     files, checks if        source → sink
        (placeholder vs     vuln code path          CVSS scoring
         real credential)   is actually called      exact line numbers
               │                   │                       │
               └───────────────────┴───────────────────────┘
                                   │
                            ┌──────▼──────┐
                            │  Together AI │
                            │ Qwen3-Coder  │
                            └─────────────┘
```

---

## What Gets Scanned

**Secrets** — 487 rules across:
```
AWS, GitHub, OpenAI, Anthropic, GCP, Azure, Cloudflare, Slack, Stripe, Twilio,
SendGrid, Docker, npm, SSH/PGP/RSA/EC keys, database URIs, JWTs, generic tokens
```

**SCA** — 19 ecosystems, 50+ lockfile formats:
```
Go, Python, JavaScript, Ruby, Rust, Java, PHP, .NET, Dart, C/C++, Haskell,
Elixir, Erlang, R, Swift, Lua, Nim, OCaml, Julia
```

**SAST** — AI analysis across 18 languages:
```
Go, Python, JavaScript, TypeScript, Java, Ruby, PHP, C#, Rust, C, C++,
Kotlin, Swift, Bash, and more — no rule files required
```

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Table (default) | `-f table` | Terminal, human review |
| JSON | `-f json` | CI pipelines, tooling |
| SARIF 2.1.0 | `-f sarif` | GitHub Code Scanning |

---

## Acknowledgments

- [Titus](https://github.com/praetorian-inc/titus) — secrets engine
- [osv-scalibr](https://github.com/google/osv-scalibr) — lockfile extraction
- [osv.dev](https://osv.dev) — vulnerability database
- [Together AI](https://together.ai) — AI inference

## License

[MIT](LICENSE)
