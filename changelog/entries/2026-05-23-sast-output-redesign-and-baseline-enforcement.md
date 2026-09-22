---
date: "2026-05-23"
stats:
    commits: 5
    insertions: 2230
    deletions: 450
title: SAST output redesign and baseline enforcement
version: v1.0.20
---

This release redesigns SAST findings output to include code-first remediation guidance, adding a new fix_code field and restructuring how remediation text is presented. It also introduces baseline enforcement with new exit-code behavior for required findings. Several scanning engines received improvements across SCA, container, license, and secrets detection.

## Improved
- **Expand scanner capabilities across SCA, containers, licenses, and secrets**: Multiple scanning engines received feature additions and behavior improvements, broadening detection coverage and intelligence across scan types. ([847ad5b](https://github.com/Shasheen8/Broly/commit/847ad5b))
- **Update CLI description and scan output formatting**: The CLI short and long descriptions now reflect the full scanner scope including SBOM and CI usage. Scan output and container behavior were polished for clarity. ([626a087](https://github.com/Shasheen8/Broly/commit/626a087))

## Breaking
- **Redesign SAST output with fix_code field and restructured remediation**: SAST findings now include a new fix_code field and remediation text is restructured. Existing integrations that parse the old output format will break. ([15db274](https://github.com/Shasheen8/Broly/commit/15db274))
- **Introduce baseline enforcement with new exit-code behavior**: Baseline enforcement adds new exit codes for missing required findings. CI scripts that relied on the previous exit-code semantics will need updating. ([626a087](https://github.com/Shasheen8/Broly/commit/626a087))

