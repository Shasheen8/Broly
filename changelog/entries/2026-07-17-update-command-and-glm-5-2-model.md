---
date: "2026-07-17"
stats:
    commits: 4
    insertions: 76
    deletions: 22
title: Update command and GLM-5.2 model
version: v1.0.40
---

This release adds a self-update command, upgrades the default SAST model to GLM-5.2, and fixes container scanning to only run when SCA is enabled. Users can now update broly in place and will see the active model name in the startup banner.

## New
- **Adds a broly update subcommand**: Running broly update reinstalls the tool from the latest release using go install, so users no longer need to manually run the install command to upgrade. ([81ed87b](https://github.com/Shasheen8/Broly/commit/81ed87b))

## Improved
- **Updates default SAST model to GLM-5.2**: The default AI model for SAST analysis switches from Qwen/Qwen3.5-9B to zai-org/GLM-5.2, and the active model name is now displayed in both the startup and report banners. ([76c395b](https://github.com/Shasheen8/Broly/commit/76c395b), [12fe777](https://github.com/Shasheen8/Broly/commit/12fe777))

## Fixed
- **Only auto-scan container images when SCA is enabled**: Container image auto-discovery and scanning now runs exclusively when SCA is enabled, preventing unintended scans when SCA is off. ([9624ff4](https://github.com/Shasheen8/Broly/commit/9624ff4))

