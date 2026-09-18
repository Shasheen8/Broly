---
date: "2026-08-18"
stats:
    commits: 2
    insertions: 1262
    deletions: 3
title: Routes subcommand and keyword matching fix
version: v1.66.0
---

This release introduces a new routes subcommand that extracts declared HTTP routes and their reachable dangerous sinks, giving users a way to map attack surface without running a full vulnerability scan. It also fixes multi-word keyword matching in vulnerability classification so phrases like "access control" no longer match unrelated substrings such as "access controller".

## New
- **Adds a routes subcommand for extracting HTTP routes and sinks**: A new `routes [path]` command extracts the HTTP routes a repository declares along with dangerous sinks reachable from each handler. It supports output formatting, sink inclusion, minimum route filtering, and parameter display flags, and is intended as input for black-box scanners rather than a vulnerability scan itself. ([be5f9b6](https://github.com/Shasheen8/Broly/commit/be5f9b6))

## Fixed
- **Requires word boundaries for multi-word keyword matching in vulnerability classification**: Multi-word keywords now match only when bounded by non-word characters on both sides, preventing false matches like "access control" matching "access controller" or "bypass access controls". This improves classification accuracy and may change which vulnerability classes are assigned to some findings. ([b044e41](https://github.com/Shasheen8/Broly/commit/b044e41))

