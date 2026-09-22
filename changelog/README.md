# About this changelog

- Live site: [https://shasheen8.github.io/Broly/](https://shasheen8.github.io/Broly/)
- Usage guide (install, scanners, demo video): [https://shasheen8.github.io/Broly/usage.html](https://shasheen8.github.io/Broly/usage.html)

Broly is a CLI-first code security scanner (secrets, SCA, SAST, workflow, IaC, containers, SBOM) with 200+ commits of release history, presented at **DEF CON 34 AppSec Village Arsenal** as "Broly: Rebuilding Code Security With Signal, Speed, and AI". Every entry here is drafted from git history by the `broly changelog` subcommand, then edited and approved by a human before it reaches the site. This page is rendered from this README by `broly changelog build`, so the repo and the public page can never drift apart.

## How it works

```
broly changelog generate --since v1.66.0 --write   # AI drafts an entry
        (human reviews and edits the markdown)
broly changelog build                              # entries -> changelog.json + feed.xml
        (push to main, then CI builds and deploys the site)
```

## Why it is built this way

### The tool is a subcommand, not a separate repo

Broly is a CLI tool, so its changelog generator is a CLI command. A maintainer who already runs `broly scan` writes release notes with `broly changelog generate`, with nothing new to install, and the generator reuses the same Together AI client (`pkg/ai`) that powers SAST and triage. Dogfooding is the point: a tool for builders should be built with itself.

### The audience rule

Entries are written for users, not maintainers. The prompt enforces a hard rule: internal refactors, CI chores, dependency bumps, and doc reorganization are omitted unless they change observable behavior (flags, commands, config, output formats, exit codes). Six commits can become two bullets if that is what the story needs.

### Diffs, not just commit messages

Commit subjects undersell most changes ("fix: word boundaries" tells a user nothing). The generator collects each commit's message, body, touched files, and line counts, and attaches trimmed diffs to the most user-facing commits. For context that never made it into a commit message, `--notes` passes maintainer intent straight into the prompt.

### Draft, review, publish

The model never publishes. It writes a draft in markdown with frontmatter, saved under `entries/`. The maintainer corrects wording, drops noise, and adds context the git history cannot show, then commits. Only reviewed entries reach the site, mirroring how Broly treats AI triage verdicts.

### Guardrails on the model

- The response is a JSON schema. Anything unparseable fails loudly instead of guessing.
- Every commit reference is validated against the real commit window. Invented SHAs are silently dropped, and real ones get exact GitHub URLs.
- The prompt says "never invent changes" and caps the window at 150 commits so the model summarizes instead of listing.

### The site is deliberately boring to deploy

`site/` is three hand-written files: `index.html`, `style.css`, and `app.js` (vanilla JS, no framework, no build step, no dependencies). GitHub Actions runs `broly changelog build` and copies the directory to Pages. What that buys:

- Nothing to npm install, and no transitive dependency can break CI.
- No build pipeline to keep green. A deploy is just a file copy.
- It still looks sharp: dark terminal aesthetic, release timeline with category colors, filter chips, commit chips linking to GitHub, per-release diff stats, and a red glow on releases containing breaking changes.

Generated output (`changelog.json`, `feed.xml`, `about.html`, `usage.html`) is gitignored and rebuilt in CI, so the repo only ever stores reviewed source.

Patterns borrowed from changelogs that do this well:

- **Stripe**: breaking-change visibility up front, so users can scan for danger before reading anything else.
- **Twilio**: an RSS feed worth subscribing to, and one-line summaries that link to detail.
- **Both**: reverse-chronological paging (4 releases per page, hash-addressable, so an RSS link like `#v1-0-28` lands on the right page).

One deliberate style rule: ASCII punctuation only, in the README, the site, and generated entries. Broly is a terminal-first tool, and its docs render in terminals, editors, RSS readers, and browsers alike.

## Working on it

### Repo layout

```
changelog/
  entries/    reviewed markdown, one file per release (frontmatter + sections)
  site/       static site: app.js fetches changelog.json, while about.html
              and usage.html are generated from this README and
              USAGE.md at build time, demo video alongside
  README.md   this file
  USAGE.md    usage guide rendered into usage.html
```

```
pkg/changelog/
  git.go       commit window collection, diffstats, repo remote resolution
  generate.go  prompt assembly, model call, JSON validation
  entry.go     entry types, markdown render/parse round-trip
  site.go      entries -> changelog.json + RSS feed + doc pages
cmd/broly/
  changelog.go the generate/build subcommands
.github/workflows/
  pages.yml    CI: build site data, deploy to GitHub Pages
```

### Tools used to build this

- Built with [opencode](https://opencode.ai), an AI coding agent, using GLM via Together AI.
- Entry drafts are generated by `zai-org/GLM-5.2` through the same Together AI client Broly uses for SAST.
- Go, cobra, and gopkg.in/yaml.v3. Vanilla JS/CSS for the site.

### Running locally

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

### Publishing checklist

1. Tag or cut the release.
2. `broly changelog generate --since <last-tag> --write`.
3. Edit the draft in `entries/`: fix wording, add context, drop noise.
4. `broly changelog build` to preview locally.
5. Commit `entries/` and push. CI deploys the site.