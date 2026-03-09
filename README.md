<p align="center">
  <img src="assets/broly-logo.png" alt="Broly" width="600"/>
</p>

<h1 align="center">Broly</h1>
<p align="center"><strong>A Berserker Product Security Tool</strong></p>

<p align="center">
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go Version"></a>
  <a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
  <a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue?style=flat" alt="Release"></a>
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat" alt="Platform"></a>
</p>

---

Single-binary security scanner combining **Secrets**, **SCA**, and **SAST** scanning. Built in Go on top of battle-tested OSS engines. Fast enough to run on every commit.

## Powered By

Broly is a thin orchestration layer over production-grade upstream engines:

| Scanner | Engine | What It Provides |
|---------|--------|-----------------|
| **Secrets** | [Poltergeist](https://github.com/ghostsecurity/poltergeist) | 100 rules, Hyperscan/regex engines, entropy filtering |
| **SCA** | [osv-scalibr](https://github.com/google/osv-scalibr) + [osv.dev](https://osv.dev) | 50+ lockfile formats, 19 ecosystems, official OSV API |
| **SAST** | [go-tree-sitter](https://github.com/smacker/go-tree-sitter) | AST-based pattern matching (Phase 2) |

Broly adds: unified `Finding` type, concurrent orchestration, CLI, SARIF/JSON/table output, and CI-friendly exit codes.

## Install

```bash
# From source (requires Go 1.26+, Vectorscan for Hyperscan support)
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build

# Vectorscan (optional, enables Hyperscan engine)
brew install vectorscan   # macOS
```

## Usage

```bash
# Scan everything (secrets + SCA + SAST)
broly scan .

# Individual scanners
broly scan . --secrets
broly scan . --sca
broly scan . --secrets --sca

# Output formats
broly scan . -f json
broly scan . -f sarif -o results.sarif

# Filter by severity
broly scan . --min-severity high

# Offline SCA (skip OSV API)
broly scan . --sca --offline
```

## What It Finds

### Secrets (100 rules via Poltergeist)

AWS, GitHub, OpenAI, Anthropic, GCP, Azure, Cloudflare, Slack, Stripe, Twilio, SendGrid, Docker, npm, Databricks, Datadog, RSA/SSH/PGP/EC keys, PostgreSQL/MySQL/MongoDB/Redis connection strings, generic API keys/secrets/passwords/tokens, JWTs, and more.

### SCA (19 ecosystems via osv-scalibr)

| Ecosystem | Formats |
|-----------|---------|
| Go | `go.mod`, stdlib version |
| JavaScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`, `uv.lock` |
| Ruby | `Gemfile.lock` |
| Rust | `Cargo.lock` |
| Java | `gradle.lockfile`, `pom.xml` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json`, `deps.json` |
| Dart | `pubspec.lock` |
| C/C++ | `conan.lock` |
| Haskell | `cabal.project.freeze`, `stack.yaml.lock` |
| Elixir/Erlang | `mix.lock` |
| R | `renv.lock` |
| Swift | `Package.resolved` |
| + more | Lua, Nim, OCaml, Julia |

### SAST

Tree-sitter based AST analysis. Coming in v0.2.

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Table | `-f table` | Human-readable CLI output |
| JSON | `-f json` | Automation, pipelines |
| SARIF 2.1.0 | `-f sarif` | GitHub Security tab, IDEs |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Findings detected |
| `2` | Error |

## Architecture

```
cmd/broly/                  Cobra CLI (thin — no business logic)
pkg/core/                   Finding, Scanner interface, Severity, Config
pkg/secrets/scanner.go      Adapter: Poltergeist → core.Finding
pkg/sca/scanner.go          Adapter: osv-scalibr + osv.dev → core.Finding
pkg/sast/engine.go          Stub: tree-sitter engine (Phase 2)
pkg/orchestrator/           Concurrent scanner coordination
pkg/report/                 JSON, SARIF, Table formatters
```

**~1,400 lines of custom Go code.** Everything else is upstream.

## License

[MIT](LICENSE) — Shasheen_B 2026
