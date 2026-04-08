# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| `main` branch | Yes |
| Older releases | No |

## Reporting a Vulnerability

**Do not report security vulnerabilities in public issues.**

Use [GitHub Security Advisories](https://github.com/Shasheen8/Broly/security/advisories/new) to report privately. This keeps the disclosure coordinated and gives us time to ship a fix before anything is public.

Include:

- Description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Affected version(s) or commit range
- Suggested fix if you have one

We will acknowledge within 48-72 hours and give credit in the advisory and release notes (unless you prefer anonymity).

## Scope

Broly sends source code snippets to Together AI for SAST analysis and AI triage. If you find a way to exfiltrate secrets through this path beyond what `FileContextSafe` already redacts, that is in scope.

Container image contents are processed locally. OSV queries send only package names and versions, not source code.
