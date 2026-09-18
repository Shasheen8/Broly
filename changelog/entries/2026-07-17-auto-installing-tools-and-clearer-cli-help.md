---
date: "2026-07-17"
stats:
    commits: 6
    insertions: 253
    deletions: 71
title: Auto-installing tools and clearer CLI help
version: v1.0.36
---

This release removes the manual pip install step for zizmor and checkov by auto-installing them into a managed venv on first use. It also overhauls the CLI banner and help text so users can see every scanner and AI flag at a glance.

## New
- **Auto-install zizmor and checkov on first use** — The --workflow and --iac scanners now create a Python venv at ~/.cache/broly/venv/ and pip install the required tools automatically, falling back to a system-installed version if present. Users no longer need to manually install zizmor or checkov before running those scans. ([a4afcf7](https://github.com/Shasheen8/Broly/commit/a4afcf7))

## Improved
- **Overhaul CLI banner and help text** — The long help output now lists every scanner, supported ecosystems, and AI feature flags in a structured layout. The startup banner uses a standard figlet font and renders correctly across terminals. ([4631822](https://github.com/Shasheen8/Broly/commit/4631822), [c46396a](https://github.com/Shasheen8/Broly/commit/c46396a), [d33ae9d](https://github.com/Shasheen8/Broly/commit/d33ae9d))

