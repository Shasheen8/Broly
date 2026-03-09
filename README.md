<p align="center">
  <img src="assets/broly-logo.png" alt="Broly" width="600"/>
</p>

<h1 align="center">Broly</h1>

<p align="center">
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
  <a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue?style=flat" alt="Release"></a>
</p>

Berserker product security scanner. Secrets, SCA, and SAST in a single binary. Built on [Poltergeist](https://github.com/ghostsecurity/poltergeist) (100 secret detection rules, Hyperscan engine), [osv-scalibr](https://github.com/google/osv-scalibr) (50+ lockfile formats across 19 ecosystems), and the [OSV.dev](https://osv.dev) vulnerability database (no API key needed, fully open).

## Quick Start

```bash
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build

# Optional: enables Hyperscan engine for faster secret scanning
brew install vectorscan
```

## Usage

```bash
# Scan current directory (secrets + SCA)
broly scan

# Scan a specific path
broly scan /path/to/project

# Individual scanners
broly scan --secrets
broly scan --sca

# Output formats
broly scan -f json
broly scan -f sarif -o results.sarif

# Filter
broly scan --min-severity high

# Offline (skip OSV API)
broly scan --sca --offline
```

## What It Finds

**Secrets** — AWS, GitHub, OpenAI, Anthropic, GCP, Azure, Cloudflare, Slack, Stripe, Twilio, SendGrid, Docker, npm, SSH/PGP/RSA keys, database connection strings, JWTs, generic tokens and passwords. 100 rules with entropy filtering.

**SCA** — Vulnerable dependencies across Go, Python, JavaScript, Ruby, Rust, Java, PHP, .NET, Dart, C/C++, Haskell, Elixir, Erlang, R, Swift, and more. Queries the open OSV.dev database. Detects Go stdlib vulnerabilities.

**SAST** — Tree-sitter based AST analysis. Coming in v0.2.

## Output Formats

`table` (default), `json`, `sarif` (SARIF 2.1.0 for GitHub Security tab and IDEs).

## Acknowledgments

Built on the shoulders of:

- [Poltergeist](https://github.com/ghostsecurity/poltergeist) — secret scanning engine
- [osv-scalibr](https://github.com/google/osv-scalibr) — lockfile extraction
- [osv.dev](https://osv.dev) — vulnerability database
- [Bearer](https://github.com/bearer/bearer) — SAST architecture reference
- [Opengrep](https://github.com/opengrep/opengrep) — rule DSL inspiration

## License

[MIT](LICENSE)
