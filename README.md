<p align="center">
  <img src="assets/broly-logo.png" alt="Broly" width="600"/>
</p>

<h1 align="center">Broly</h1>

<p align="center">
  <a href="https://github.com/Shasheen8/Broly"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://github.com/Shasheen8/Broly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License"></a>
  <a href="https://github.com/Shasheen8/Broly/releases"><img src="https://img.shields.io/github/v/release/Shasheen8/Broly?style=flat&label=Release" alt="Release"></a>
</p>

Berserker product security scanner. Secrets, SCA, and SAST in a single binary.

## Install

Download a pre-built binary from [Releases](https://github.com/Shasheen8/Broly/releases).

Or build from source (requires [Vectorscan](https://github.com/VectorCamp/vectorscan) for the Hyperscan secrets engine):

```bash
brew install vectorscan

git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build
```

## Usage

```bash
broly scan                           # scan current directory
broly scan /path/to/project          # scan specific path

broly scan --secrets                 # secrets only
broly scan --sca                     # SCA only

broly scan -f json                   # JSON output
broly scan -f sarif -o results.sarif

broly scan --min-severity high
broly scan --sca --offline           # skip OSV API
```

## What It Finds

**Secrets** - 100 rules, entropy filtering, Hyperscan engine

```
AWS, GitHub, OpenAI, Anthropic, GCP, Azure, Cloudflare, Slack, Stripe, Twilio,
SendGrid, Docker, npm, SSH/PGP/RSA/EC keys, database URIs, JWTs, generic tokens
```

**SCA** - 19 ecosystems, 50+ lockfile formats

```
Go, Python, JavaScript, Ruby, Rust, Java, PHP, .NET, Dart, C/C++, Haskell,
Elixir, Erlang, R, Swift, Lua, Nim, OCaml, Julia, including Go stdlib vulns
```

**SAST** - AST-based analysis, coming in v0.2

## Output Formats

| Format | Flag |
|--------|------|
| Table (default) | `-f table` |
| JSON | `-f json` |
| SARIF 2.1.0 | `-f sarif` |

## Acknowledgments

- [Titus](https://github.com/praetorian-inc/titus) — secrets engine
- [osv-scalibr](https://github.com/google/osv-scalibr) — lockfile extraction
- [osv.dev](https://osv.dev) — vulnerability database

## License

[MIT](LICENSE)
