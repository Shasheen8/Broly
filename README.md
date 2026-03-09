<p align="center">
  <img src="assets/broly-logo.png" alt="Broly" width="600"/>
</p>

<h1 align="center">Broly</h1>

<p align="center">
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
  <a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue?style=flat" alt="Release"></a>
</p>

Berserker product security scanner. Secrets, SCA, and SAST in a single binary.

## Quick Start

Download a pre-built binary from [Releases](https://github.com/Shasheen8/Broly/releases), or build from source:

```bash
brew install vectorscan   # build dependency
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build
```

## Usage

```bash
broly scan                          # scan current directory
broly scan /path/to/project         # scan specific path
broly scan --secrets                # secrets only
broly scan --sca                    # SCA only
broly scan -f json                  # JSON output
broly scan -f sarif -o results.sarif
broly scan --min-severity high
broly scan --sca --offline          # skip OSV API
```

## What It Finds

**Secrets** — 100 rules, entropy filtering, Hyperscan engine

```
  AWS, GitHub, OpenAI, Anthropic, GCP, Azure, Cloudflare, Slack, Stripe, Twilio, SendGrid, Docker, npm,
  SSH/PGP/RSA/EC keys, database connection strings, JWTs, generic tokens and passwords
```

**SCA** — 19 ecosystems, 50+ lockfile formats, OSV.dev database

```
  Go, Python, JavaScript, Ruby, Rust, Java, PHP, .NET, Dart, C/C++, Haskell, Elixir, Erlang, R, Swift,
  Lua, Nim, OCaml, Julia — including Go stdlib vulnerabilities
```

**SAST** — tree-sitter AST analysis, coming in v0.2

## Output Formats

- `table` (default)
- `json`, `sarif` (SARIF 2.1.0)

## Acknowledgments

- [Poltergeist](https://github.com/ghostsecurity/poltergeist) — secret scanning engine
- [osv-scalibr](https://github.com/google/osv-scalibr) — lockfile extraction
- [osv.dev](https://osv.dev) — vulnerability database
- [Opengrep](https://github.com/opengrep/opengrep) — rule DSL inspiration

## License

[MIT](LICENSE)
