# Contributing to Broly

## Reporting Bugs

Check existing issues first. When filing a new one, include:

- Steps to reproduce
- Expected vs actual behavior
- Broly version (`broly version`), OS, Go version
- Relevant logs or output

## Suggesting Features

Open an issue with a clear description, the problem it solves, and any alternatives you considered.

## Pull Requests

1. Fork the repo and branch from `main`
2. Make your changes
3. Run `make check` (fmt, vet, test, build)
4. Submit a PR with a clear description

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/Broly.git
cd Broly

# Build
make build

# Run checks
make check

# Run tests
go test ./...

# Build with Hyperscan (macOS)
brew install vectorscan
make build
```

AI features require `TOGETHER_API_KEY` set in your environment.

## Code Style

- Standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and small
- Error handling: return errors, don't swallow them silently
- No unnecessary abstractions -- three similar lines is better than a premature helper

## Project Structure

```
Broly/
cmd/broly/         CLI entry point (Cobra)
pkg/
  core/            Finding, Config, Severity, Scanner interface
  ai/              Shared Together AI client
  secrets/         Titus adapter + AI false positive filter
  sca/             osv-scalibr + osv.dev + AI reachability
  sast/            AI SAST engine (prompt, parser, language detection)
  container/       Container image scanner (APK, DPKG, RPM + OSV)
  triage/          AI verdict, confidence, fix suggestion
  baseline/        Suppress/require rules
  suppress/        Inline broly:ignore handling
  cache/           Incremental scan hash cache
  report/          Table, JSON, SARIF formatters
  orchestrator/    Concurrent scanner coordination
```

## Commit Messages

Short, natural, present tense. No conventional commit prefixes unless they fit naturally.

```
add container package extraction and OSV vuln matching
fix baseline pipeline skipping filters on load failure
tighten readme
```

## Testing

- `go test ./...` for all tests
- `go test ./pkg/sast/ -v` for a specific package
- Test container scanning: `go run ./cmd/broly scan --container alpine:3.19`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
