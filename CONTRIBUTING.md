# Contributing to Broly

## Reporting Bugs

Check existing issues first. Include:

- Steps to reproduce
- Expected vs actual behavior
- Broly version (`broly version`), OS, Go version
- Relevant logs or output

## Suggesting Features

Open an issue with a clear description and the problem it solves.

## Pull Requests

1. Fork the repo and branch from `main`
2. Make your changes
3. Run `make check` (fmt, vet, test, build)
4. Submit a PR with a clear description

## Development Setup

```bash
git clone https://github.com/Shasheen8/Broly.git
cd Broly
make build          # build the CLI
make check          # fmt + vet + test + build
go test ./...       # run tests
```

AI features require `TOGETHER_API_KEY` set in your environment.

zizmor and checkov auto-install on first use. To pre-install manually: `pip install zizmor checkov`.

## Code Style

- Standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and small
- Return errors, don't swallow them silently
- No unnecessary abstractions

## Project Structure

```
Broly/
cmd/
  broly/         CLI entry point (Cobra)
  broly-app/     GitHub App webhook server
pkg/
  ai/            Together AI client (GLM-5.2)
  core/          Finding, Config, Severity, Scanner interface
  secrets/       Titus adapter + AI false positive filter
  sca/           osv-scalibr + osv.dev + AI reachability + package intelligence
  sast/          AI SAST engine (prompt, parser, slice builder, language detection)
  container/     Container image scanner (APK, DPKG, RPM + OSV)
  license/       License detection and policy engine
  sbom/          CycloneDX and SPDX formatters
  triage/        AI verdict, confidence, fix suggestion, adversarial verify
  chain/         Exploit chain synthesis
  workflow/      GitHub Actions scanning (zizmor)
  iac/           IaC scanning (checkov)
  sca/           Supply chain malicious-package audit (depx)
  baseline/      Suppress/require rules
  suppress/      Inline broly:ignore handling
  cache/         Incremental scan hash cache
  report/        Table, JSON, SARIF formatters
  orchestrator/  Concurrent scanner coordination
  toolinstall/   Auto-install zizmor/checkov via venv
```

## Commit Messages

Short, natural, present tense. No conventional commit prefixes unless they fit naturally.

```
add container package extraction and OSV vuln matching
fix baseline pipeline skipping filters on load failure
update readme
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.