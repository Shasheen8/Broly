# Broly Changelog

Live site: https://shasheen8.github.io/Broly/ | RSS: https://shasheen8.github.io/Broly/feed.xml

An AI-generated changelog for [Broly](https://github.com/Shasheen8/Broly), a CLI-first code security scanner (secrets, SCA, SAST, workflow, IaC, containers, SBOM) with 200+ commits of release history. Broly is an active open-source project that was presented at **DEF CON 34 AppSec Village Arsenal** as "Broly: Rebuilding Code Security With Signal, Speed, and AI".

This directory holds both halves of the changelog system:

1. A developer-facing tool: the `broly changelog` subcommand, part of the CLI itself.
2. A public-facing static site: `site/`, deployed to GitHub Pages on every push.

```
broly changelog generate --since v1.66.0 --write   # AI drafts an entry
        (human reviews and edits the markdown)
broly changelog build                              # entries -> changelog.json + feed.xml
        (push to main; CI builds and deploys the site)
```

---

## Why it is built this way

### The tool is a subcommand, not a separate repo

Broly is a CLI tool, so its changelog generator is a CLI command. A maintainer who already runs `broly scan` in this repo writes release notes with `broly changelog generate`. There is nothing new to install, no second service to run, and the generator reuses the same Together AI client (`pkg/ai`) that powers SAST and triage. Dogfooding was the whole point: a tool for builders should be built with itself.

### The audience rule

A changelog has two possible audiences: maintainers (who know the code) and users (who only see releases). This one is written for users. The generation prompt enforces a hard rule: internal refactors, CI chores, dependency bumps, and doc reorganization are omitted unless they change observable behavior (flags, commands, config, output formats, exit codes). Six commits can become two bullets if that is what the story needs.

### Diffs, not just commit messages

Commit subjects undersell most changes ("fix: word boundaries" tells a user nothing). The generator collects each commit's message, body, touched files, and line counts, and attaches trimmed diffs to the most user-facing commits (feature work, anything touching `cmd/`, anything with breaking-sounding language). The model reads what actually changed and writes what it means. For context that never made it into a commit message, `--notes "why we shipped this"` passes maintainer intent straight into the prompt.

### Draft, review, publish

The model never publishes. It writes a draft in a format designed for human editing: markdown with frontmatter, saved under `entries/`. The maintainer corrects wording, drops noise, and adds context the git history cannot show, then commits. Only reviewed entries reach the site. This mirrors how security tooling handles LLM output elsewhere in Broly (AI triage proposes verdicts; humans accept them), so the trust model is consistent across the product.

### Guardrails on the model

- The response is a JSON schema; anything unparseable fails loudly instead of guessing.
- Every commit reference the model returns is validated against the real commit window; invented SHAs are silently dropped and real ones get exact GitHub URLs.
- The prompt says "never invent changes" and caps the window at 150 commits so the model summarizes instead of listing.

### The site is deliberately boring to deploy

`site/` is three files: `index.html`, `style.css`, `app.js` (vanilla JS, no framework, no build step, no dependencies) plus the JSON the Go tool renders from entries. GitHub Actions runs `broly changelog build` and copies the directory to Pages. Nothing to npm install, nothing that can break CI with a transitive dependency, and it still looks sharp: dark terminal aesthetic, release timeline with category colors, filter chips, commit chips linking to GitHub, per-release diff stats, and a red glow on releases containing breaking changes. The build output (`changelog.json`, `feed.xml`) is gitignored and regenerated in CI, so the repo only ever stores reviewed source.

Patterns borrowed from changelogs that do this well (Stripe, Twilio): breaking-change visibility up front, one-line summaries with links to detail, an RSS feed for subscribers, and reverse-chronological paging (4 releases per page, hash-addressable, so an RSS link like `#v1-0-28` lands on the right page).

One deliberate style rule: ASCII punctuation only, in the README, the site, and generated entries. Broly is a terminal-first tool, and its docs render in terminals, editors, RSS readers, and browsers alike.

---

## Layout

```
changelog/
  entries/    reviewed markdown, one file per release (frontmatter + sections)
  site/       static site; app.js fetches changelog.json
  README.md   this file
```

```
pkg/changelog/
  git.go       commit window collection, diffstats, repo remote resolution
  generate.go  prompt assembly, model call, JSON validation
  entry.go     entry types, markdown render/parse round-trip
  site.go      entries -> changelog.json + RSS feed
cmd/broly/
  changelog.go the generate/build subcommands
.github/workflows/
  pages.yml    CI: build site data, deploy to GitHub Pages
```

## Tools used to build this

- Built with [opencode](https://opencode.ai), an AI coding agent, using GLM via Together AI.
- Entry drafts are generated by `zai-org/GLM-5.2` through the same Together AI client Broly uses for SAST.
- Go, cobra, gopkg.in/yaml.v3; vanilla JS/CSS for the site.

## Running locally

```bash
export TOGETHER_API_KEY=your_key_here

broly changelog generate --since v1.66.0          # draft to stdout
broly changelog generate --since v1.66.0 --write  # save draft under entries/
broly changelog build                             # render site data

# preview
cd changelog/site && python3 -m http.server
```

Backfilling a historical release tag-to-tag:

```bash
broly changelog generate --since v1.0.20 --until v1.0.28 --version v1.0.28 --write
```

## Publishing checklist

1. Tag or cut the release.
2. `broly changelog generate --since <last-tag> --write`.
3. Edit the draft in `entries/`: fix wording, add context, drop noise.
4. `broly changelog build` to preview locally.
5. Commit `entries/` and push; CI deploys the site.