---
date: "2026-08-02"
stats:
    commits: 4
    insertions: 1265
    deletions: 172
title: Diff scoping, vuln-class hunting, faster scans
version: v1.52.0
---

This release adds line-level diff scoping for PR scans, vulnerability class focus flags for targeted bug hunting, and a standalone container auto-discovery mode. It also significantly reduces scan timeouts and sorts findings critical-first, plus fixes version detection in the update command.

## New
- **Add vulnerability class focus flags for targeted SAST hunting**: New flags like --idor, --xss, --sqli, --rce, and --ssrf let you focus SAST scans on specific vulnerability classes, injecting per-class guidance into the AI triage prompt and filtering final findings to only those classes. ([12d2d15](https://github.com/Shasheen8/Broly/commit/12d2d15))
- **Add line-level diff scoping for PR scans**: Scans on pull requests now scope SAST findings to only the changed lines in the diff, reducing noise from pre-existing issues and focusing review attention on new code. ([12d2d15](https://github.com/Shasheen8/Broly/commit/12d2d15))
- **Add --auto-containers flag for standalone Dockerfile base image scanning**: Container scanning is no longer coupled to SCA; the new --auto-containers flag auto-discovers and scans Dockerfile base images independently of other scanner selections. ([13fcd62](https://github.com/Shasheen8/Broly/commit/13fcd62))
- **Add --short flag to version command**: The version command now accepts --short to print only the version string, which also fixes version detection logic in the update command. ([dd8421b](https://github.com/Shasheen8/Broly/commit/dd8421b))

## Improved
- **Reduce scan timeouts and sort findings critical-first**: Total scan, triage, adversarial, and chain timeouts are reduced from 40 minutes to 9 minutes, and findings in PR comments are now sorted by severity (critical first) with SAST findings prioritized over SCA. ([9bedce3](https://github.com/Shasheen8/Broly/commit/9bedce3))

## Fixed
- **Fix update command version detection**: The update command now correctly detects the installed version before and after running go install, preventing false success reports when the install fails or the version is unchanged. ([dd8421b](https://github.com/Shasheen8/Broly/commit/dd8421b))

