---
date: "2026-08-02"
stats:
    commits: 5
    insertions: 85
    deletions: 23
title: Bug fixes and expanded help docs
version: v1.63.0
---

This release fixes several bugs that caused findings to be dropped or hidden from output, and improves reliability of AI-backed scans. It also expands the CLI help text with vulnerability class listings and CWE references so users can quickly find the right scanner flags.

## Improved
- **Expand CLI help with vulnerability classes and CWE references**: The help text now lists all supported SAST vulnerability classes with their corresponding CWE IDs and scanner flags, making it easier to target specific vulnerability categories. ([a96eea1](https://github.com/Shasheen8/Broly/commit/a96eea1))

## Fixed
- **Retry transient AI API errors with backoff**: 502, 503, and 429 responses from the AI provider are now retried up to 3 times with exponential backoff, reducing unnecessary fallbacks and scan failures. ([8bc55f1](https://github.com/Shasheen8/Broly/commit/8bc55f1))
- **Allow same-type exploit chains when 2+ critical findings exist**: Exploit chain generation no longer requires findings from different scanner types. Same-type chains are now produced when that is all that is available. ([9fbed4d](https://github.com/Shasheen8/Broly/commit/9fbed4d))
- **Preserve secrets findings with zero line numbers in diff-scoped scans**: Secrets findings that previously reported zero line numbers were dropped by diff scoping. Line numbers are now clamped to a minimum of 1 so these findings are retained. ([25b465b](https://github.com/Shasheen8/Broly/commit/25b465b))
- **Render IaC findings in CLI table output**: IaC findings were missing from the CLI table view due to a missing case in the scan-type switch. They now appear alongside SAST and workflow findings. ([1270b0f](https://github.com/Shasheen8/Broly/commit/1270b0f))

