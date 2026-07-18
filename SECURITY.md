# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| `main` branch | Yes |
| Older releases | No |

## Reporting a Vulnerability

**Do not report security vulnerabilities in public issues.**

Use [GitHub Security Advisories](https://github.com/Shasheen8/Broly/security/advisories/new) to report privately.

Include:

- Description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Affected version(s) or commit range
- Suggested fix if you have one

We will acknowledge within 48-72 hours and give credit in the advisory and release notes (unless you prefer anonymity).

## Scope

Broly sends source code snippets to Together AI (GLM-5.2) for SAST analysis, AI triage, and adversarial verification. All file content is redacted for secrets before being sent to the model. If you find a way to exfiltrate secrets through this path, that is in scope.

Container image contents are processed locally. OSV queries send only package names and versions, not source code.

zizmor and checkov run locally in an isolated Python venv. They do not send source code to any external service.