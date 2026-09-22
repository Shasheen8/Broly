---
date: "2026-09-22"
stats:
    commits: 19
    insertions: 3636
    deletions: 420
title: Changelog subcommand and public site
version: v1.78.0
---

This release introduces a new changelog subcommand that generates a public changelog site from markdown entries. Users can now run changelog commands to build site data, and the project publishes a paginated, searchable changelog with About and Usage pages. The feature also backfills five historical release entries.

## New
- **Add changelog subcommand and public site generation**: A new changelog subcommand builds a static site from markdown entries in changelog/entries. The site includes pagination, an About page rendered from the README, a Usage page with full help output and a demo video, and a table of contents sidebar with scroll-spy navigation. ([f813d35](https://github.com/Shasheen8/Broly/commit/f813d35), [464533e](https://github.com/Shasheen8/Broly/commit/464533e), [8b05762](https://github.com/Shasheen8/Broly/commit/8b05762))

## Fixed
- **Fix changelog entry formatting and relative dates**: Strips leftover parentheses from commit chips in changelog item details and corrects singular month/year labels in relative date display on the site. ([3749dcf](https://github.com/Shasheen8/Broly/commit/3749dcf), [ef788dd](https://github.com/Shasheen8/Broly/commit/ef788dd))

