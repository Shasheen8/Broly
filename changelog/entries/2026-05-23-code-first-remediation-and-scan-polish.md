---
date: "2026-05-23"
stats:
    commits: 5
    insertions: 2230
    deletions: 450
title: Code-first remediation and scan polish
version: v1.0.20
---

This release redesigns SAST output to include concrete fix code alongside remediation guidance, and polishes scan output formatting and container behavior across all scanners. It also introduces baseline finding enforcement, new exit codes for missing required findings, and broader language and scanner coverage.

## New
- **Adds fix code blocks to SAST findings and PR comments**: Findings now carry a separate fix_code field rendered as a code block in results and pull request comments, giving developers copy-pasteable remediation snippets instead of prose-only suggestions. ([15db274](https://github.com/Shasheen8/Broly/commit/15db274), [847ad5b](https://github.com/Shasheen8/Broly/commit/847ad5b))
- **Adds baseline finding enforcement with new exit codes**: The CLI now distinguishes between findings detected, required baseline findings missing, and both conditions simultaneously, returning distinct error messages and exit behavior for each case. ([626a087](https://github.com/Shasheen8/Broly/commit/626a087), [847ad5b](https://github.com/Shasheen8/Broly/commit/847ad5b))

## Improved
- **Polishes scan output formatting and container behavior**: Scan output, table formatting, and report generation have been refined across SAST, SCA, secrets, SBOM, and container scanners for cleaner, more consistent results. ([626a087](https://github.com/Shasheen8/Broly/commit/626a087), [847ad5b](https://github.com/Shasheen8/Broly/commit/847ad5b))
- **Expands SAST language support and scanner coverage**: Additional language parsers, SCA reachability intelligence, license scanning, and scanignore capabilities have been added, broadening the set of projects Broly can analyze out of the box. ([847ad5b](https://github.com/Shasheen8/Broly/commit/847ad5b))

