---
date: "2026-07-17"
stats:
    commits: 8
    insertions: 5174
    deletions: 102
title: Agentic triage and new scanners
version: v1.0.28
---

This release adds agentic AI triage that uses repo search tools to verify SAST findings, along with opt-in adversarial verification and exploit chain synthesis for high-confidence true positives. It also introduces three new scanner types: GitHub Actions workflows, infrastructure-as-code, and malicious-package supply chain audits, each requiring an external binary that is auto-detected at runtime.

## New
- **Adds agentic SAST triage with repo tool use**: AI triage now runs an agent loop with file-read and code-search tools to trace data flow across the repo before assigning a verdict, replacing the previous single-prompt approach. This significantly improves false-positive reduction for SAST findings. ([269f4b2](https://github.com/Shasheen8/Broly/commit/269f4b2), [9d65a8b](https://github.com/Shasheen8/Broly/commit/9d65a8b))
- **Adds adversarial verification for critical SAST true positives**: The new --adversarial flag (requires --ai-triage) runs a two-stage falsification and deep-verify pass on critical SAST true positives, downgrading disproven findings to false positives and confirming real exploitable paths. Findings gain an AdversarialVerdict field in output. ([3c7eae7](https://github.com/Shasheen8/Broly/commit/3c7eae7))
- **Adds exploit chain synthesis across scanner types**: The new --exploit-chains flag (requires --ai-triage) links 2-4 cross-scanner true positives into multi-step attack narratives, with validation that fingerprints resolve to real findings and no invented artifacts. Each finding in a chain gets a chain ID in output. ([df2f80f](https://github.com/Shasheen8/Broly/commit/df2f80f))
- **Adds GitHub Actions workflow scanning via zizmor**: The new --workflow flag scans .github/workflows and composite action manifests using the zizmor binary, which must be installed separately. Findings include severity, snippet, and remediation suggestions with rule IDs prefixed zizmor. ([6cd1096](https://github.com/Shasheen8/Broly/commit/6cd1096))
- **Adds IaC scanning via checkov**: The new --iac flag scans Terraform, Kubernetes, Helm, and CloudFormation files using the checkov binary, which must be installed separately. Findings include severity mapped from AWS Security Hub and CIS risk levels with rule IDs prefixed broly.iac. ([33f63d0](https://github.com/Shasheen8/Broly/commit/33f63d0))
- **Adds supply chain malicious-package audit**: The new --supply-chain flag audits dependencies against known-malicious package feeds using the depx binary, which must be installed separately. Malicious-package findings are always CRITICAL severity and are never suppressed by baselines. ([a78df40](https://github.com/Shasheen8/Broly/commit/a78df40))

## Improved
- **Updates broly-app pipeline to match CLI capabilities**: The local webhook server now runs the same scanner pipeline as the CLI, including agentic triage, workflow, and IaC scanning, so PR-experience testing reflects actual CLI behavior. ([b63c909](https://github.com/Shasheen8/Broly/commit/b63c909))

