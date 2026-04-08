# Broly - Berserker Vulnerability Scanner

## Master Plan

**Author:** Shasheen B
**Created:** 2026-03-08
**Last Updated:** 2026-04-08
**Status:** Phases 1-8C, 11B, 11D complete. 11C deferred. Only 11A remains before Togethercomputer org push.

---

## 1. Vision

Broly is a single-binary, production-grade security scanner that unifies **SAST**, **SCA**, and **Secrets** scanning. Built in Go for speed, zero external rule files, and easy CI/CD integration.

**Name origin:** Broly - the Berserker. Relentless, powerful, leaves nothing standing.

**Direction:** AI-first. No rule files. No rule engine. No YAML. The LLM traces data flow from source to sink, infers CVSS scores, and pinpoints exact line numbers - finding what static rules miss.

---

## 2. Design Decisions (Current)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | **Go 1.26** | Fast compilation, single binary, import upstream engines directly |
| SAST engine | **Together.ai - Qwen/Qwen3-Coder-Next-FP8** | No rule files, no rule engine. AI traces data flow source-to-sink, infers CVSS, pinpoints line numbers |
| SCA engine | **osv-scalibr + osv.dev** | Google's official lockfile extraction (50+ formats) + OSV API with retry/batching |
| Secrets engine | **Titus** | 487 rules (NoseyParker + Kingfisher), Hyperscan engine, live secret validation |
| AI provider | **Together.ai** | OSS model access, no vendor lock-in, `together-go` official Go SDK |
| AI client | **`pkg/ai/` shared package** | Single `Client` struct wrapping `together-go`, reused across SAST, Secrets, SCA |
| Output | **JSON, SARIF 2.1.0, CLI table** | JSON for automation, SARIF for GitHub Security tab, table for humans |
| Distribution | **Single binary** | GoReleaser: linux/amd64 + linux/arm64 via native runners; macOS build from source |

---

## 3. Inspiration Sources (app_sec_toolset)

### 3.1 Together Go SDK
- **What:** `github.com/togethercomputer/together-go` v0.6.0 - official Go SDK for Together.ai
- **What we use:** `ChatCompletionNew()` with system/user message structure, OpenAI-compatible API
- **Key insight:** Reads `TOGETHER_API_KEY` automatically from env via `together.NewClient()`

### 3.2 Titus (Secrets engine - imported directly)
- **What:** High-performance Go secrets scanner by Praetorian. Port of NoseyParker with Hyperscan + Go regex engines
- **What we use:** `titus.NewScanner()`, `ScanFile()` - thin adapter in `pkg/secrets/scanner.go`
- **License:** Apache 2.0

### 3.3 osv-scalibr + osv.dev (SCA engine)
- **What:** Google's official lockfile extraction + OSV vulnerability database
- **What we use:** `scalibr.ScanFilesystem()` for lockfile parsing, `osv.dev/bindings/go` for batch API queries
- **Key insight:** Batch queries (up to 1000/batch) to osv.dev are fast and free

---

## 4. Architecture

### Current Architecture (Phases 1-4)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                            GitHub                                   │
  │                                                                     │
  │   PR opened / commit pushed          Push to main / manual         │
  └───────────┬────────────────────────────────────┬────────────────────┘
              │                                    │
              └──────────────┬─────────────────────┘
                             │  (one trigger fires at a time)
                             ▼
              ┌──────────────────────────────────────┐
              │         broly scan                   │
              │         single Go binary             │
              │         pkg/orchestrator             │
              │                                      │
              │  PR mode: git diff, changed files    │
              │  Full mode: entire repo              │
              │                                      │
              │  3 scanners run concurrently         │
              │  findings streamed to aggregator     │
              │  → dedup → suppress → baseline       │
              │  → severity filter                   │
              └───────┬──────────┬──────────┬────────┘
                      │          │          │
                      ▼          ▼          ▼
             ┌──────────┐ ┌──────────┐ ┌──────────────────────┐
             │ SECRETS  │ │   SCA    │ │        SAST          │
             │          │ │          │ │                      │
             │ Titus    │ │osv-      │ │  Together.ai         │
             │ 487 rules│ │scalibr   │ │  Qwen3-Coder         │
             │ Hyperscan│ │50+ fmt   │ │                      │
             │          │ │    +     │ │  No rule files       │
             │ optional │ │osv.dev   │ │  No rule engine      │
             │ AI false │ │batch CVE │ │  Source → sink       │
             │ positive │ │          │ │  dataflow, CVSS      │
             │ filter   │ │ optional │ │  18 languages        │
             │          │ │ AI reach-│ │                      │
             │          │ │ ability  │ │                      │
             └────┬─────┘ └────┬─────┘ └──────────┬───────────┘
                  │            │                   │
                  └────────────┼───────────────────┘
                               │
                               ▼
              ┌──────────────────────────────────────┐
              │         Together.ai                  │
              │         Qwen/Qwen3-Coder-Next-FP8    │
              │                                      │
              │  SAST    → file → LLM → findings     │
              │  Secrets → snippet → TRUE/FALSE      │
              │  SCA     → CVE → REACHABLE/NOT       │
              └───────────────┬──────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────────────┐
              │           pkg/report                 │
              │                                      │
              │  Table  →  terminal output           │
              │  JSON   →  CI pipelines              │
              │  SARIF  →  GitHub Security tab       │
              └──────┬───────────┬───────────┬───────┘
                     │           │           │
                     ▼           ▼           ▼
              PR Comment     SARIF        Artifacts
              findings       GitHub       JSON + SARIF
              table          Security     30-day
              severity       tab          retention
              icons          (via GHA
              updates        upload-sarif)
              in-place
              (via GHA
              github-script)
```

### Phase 5 Addition — AI Triage

```
                                  [scan results]
                                        │
                                        ▼
                              AI Triage  (Together.ai)
                              ┌──────────────────────────┐
                              │  TRUE_POSITIVE  → keep   │
                              │  FALSE_POSITIVE → filter │
                              │  fix suggestion attached  │
                              └─────────────┬────────────┘
                                            │
                                            ▼
                                     PR Comment
                              ┌──────────────────────────┐
                              │  TP/FP verdict per row   │
                              │  suggested fix inline     │
                              │  [ ] checkbox per finding │
                              └─────────────┬────────────┘
                                            │
                              dev checks / unchecks box
                                            │
                                            ▼
                               Developer Feedback Loop
                              ┌──────────────────────────┐
                              │  fingerprint written to   │
                              │  .broly-baseline.yaml     │
                              │  suppressed on next scan  │
                              └──────────────────────────┘
```

### Phase 7 Addition — GitHub App and Centralized Storage

```
  GitHub Org
    │
    └── install Broly App (one click, covers all repos)
                │
                ├── PR opened ──────────────────────────────────────────────┐
                │                                                            │
                └── push to main ────────────────────────────────────────────┤
                                                                             │
                                                                             ▼
                                                                  Webhook Handler
                                                                  (hosted service)
                                                                             │
                                                                             ▼
                                                                    broly scan
                                                                             │
                                          ┌──────────────────────────────────┤
                                          │                                  │
                                          ▼                                  ▼
                                   Check Run                          PR Comment
                                   inline annotations                 findings table
                                   on exact diff line                 updates in-place
                                   pass/fail status                   resolved when fixed
                                          │                                  │
                                          └──────────────┬───────────────────┘
                                                         │
                                                         ▼
                                              ┌──────────────────────┐
                                              │        S3            │
                                              │  raw SARIF/JSON      │
                                              │  per scan artifact   │
                                              │  audit trail         │
                                              └──────────┬───────────┘
                                                         │
                                                         ▼
                                              ┌──────────────────────┐
                                              │      DynamoDB        │
                                              │  findings index      │
                                              │  per repo/org        │
                                              │  query by severity   │
                                              │  fingerprint, date   │
                                              └──────────────────────┘
```

### How Broly Differs from ai-sast (Rivian)

| Dimension | ai-sast (Rivian) | Broly |
|-----------|-----------------|-------|
| **Scope** | SAST only | Secrets + SCA + SAST in one binary |
| **AI models** | Gemini (scan) + Claude/Bedrock (validate) — dual model | Single model: Qwen/Qwen3-Coder-Next-FP8 via Together.ai |
| **Secrets scanning** | None | Titus: 487 rules, Hyperscan engine, AI false positive filter |
| **SCA** | None | osv-scalibr (50+ formats) + osv.dev CVE database + AI reachability |
| **Rule engine** | Structured scan approach | No rules, no YAML, no maintenance — LLM reasons over raw source |
| **Validation step** | Separate Claude/Bedrock pass validates all findings | AI filter is per-scanner and optional (flag-gated to control cost) |
| **Historical context** | Vulnerability inventory fed to Gemini | Not yet — planned as findings DB in Phase 6 |
| **Feedback loop** | Checkbox → SQLite/Databricks → fed to LLM | Checkbox → `.broly-baseline.yaml` → auto-suppressed on next scan (Phase 5 complete) |
| **Reports** | HTML reports + metrics | JSON, SARIF, terminal table |
| **GitHub integration** | PR comments | PR comments + SARIF → GitHub Security tab |
| **Distribution** | Python, runs in CI only | Single Go binary — `go install`, pre-built releases, or CI |
| **Speed** | Python, per-file API calls | Go, concurrent workers, Hyperscan for secrets |

### Core Interface

```go
type Scanner interface {
    Name() string
    Type() ScanType
    Init(cfg *Config) error
    Scan(ctx context.Context, paths []string, findings chan<- Finding) error
    Close() error
}
```

Every scanner streams `core.Finding` to a shared channel. The orchestrator runs all three concurrently and aggregates results.

---

## 5. Project Structure

```
Broly/
├── cmd/broly/main.go              # CLI entry (Cobra) - thin, no business logic
├── pkg/
│   ├── core/                      # Unified types (Finding, Scanner, Severity, Config)
│   ├── ai/client.go               # Shared Together.ai client (wraps together-go SDK)
│   ├── secrets/
│   │   ├── scanner.go             # Adapter: Titus + core.Finding (487 rules, Hyperscan)
│   │   └── validator.go           # AI false positive filter (--ai-filter-secrets)
│   ├── sca/
│   │   ├── scanner.go             # Adapter: osv-scalibr + osv.dev + core.Finding
│   │   └── reachability.go        # AI reachability analysis (--ai-sca-reachability)
│   ├── sast/
│   │   ├── engine.go              # AI SAST orchestrator (worker pool, file walking, incremental)
│   │   ├── together.go            # Together.ai client wrapper for SAST
│   │   ├── prompt.go              # Security analysis prompt (source/sink/dataflow)
│   │   ├── parser.go              # LLM response parser (extracts findings, line numbers)
│   │   └── lang.go                # Language detection (18 languages, skip dirs)
│   │   ├── baseline/                  # Suppress known FPs + require specific findings
│   ├── suppress/                  # Inline broly:ignore comment handling
│   ├── cache/                     # SHA256 file hash cache for incremental SAST
│   ├── orchestrator/              # Concurrent scanner coordination + post-processing pipeline
│   └── report/                    # JSON, SARIF 2.1.0, CLI table formatters
├── .broly.yaml                    # Default project config (min_severity, exclude_paths, workers)
├── .broly-baseline.yaml           # Baseline contract (suppress FPs, require detections)
├── Makefile
├── .goreleaser.yml
├── go.mod
└── go.sum
```

---

## 6. Phases

### Phase 1 - Foundation (Complete - 2026-03-08)

- [x] Go 1.26 module, project skeleton, Makefile, GoReleaser
- [x] `pkg/core/` - unified Finding, Scanner interface, Severity, Config
- [x] `pkg/secrets/` - thin adapter over Titus (487 rules, Hyperscan engine, live secret validation)
- [x] `pkg/sca/` - thin adapter over osv-scalibr + osv.dev (19 ecosystems, 50+ formats)
- [x] `pkg/orchestrator/` - concurrent scanner coordination with context-aware shutdown
- [x] `pkg/report/` - JSON, SARIF 2.1.0, CLI table formatters
- [x] `cmd/broly/` - Cobra CLI (scan, version, validate-rules), correct exit codes (0/1/2)
- [x] CI/CD: GitHub Actions build/test + auto-patch tagging + matrix release pipeline
- [x] Release: linux/amd64 + linux/arm64 via native ubuntu runners; macOS via source build

**Metrics:**
- 487 secret detection rules (via Titus - NoseyParker + Kingfisher)
- 19 SCA ecosystems, 50+ lockfile formats (via osv-scalibr)
- 3 output formats (JSON, SARIF, table)

### Phase 2 - AI-Powered Scanning (Complete - 2026-03-09)

**Shipped:** AI across all three scanners. No tree-sitter. No rule files. No rule engine.

**SAST:**
- [x] `pkg/ai/client.go` - shared Together.ai client wrapping official `together-go` SDK
- [x] `pkg/sast/engine.go` - concurrent worker pool, file walking, language filtering
- [x] `pkg/sast/prompt.go` - structured security analysis prompt (source/sink/dataflow/CVSS)
- [x] `pkg/sast/parser.go` - LLM response parser (findings, severity, line numbers, CWE)
- [x] `pkg/sast/lang.go` - language detection across 18 languages
- [x] Default model: `Qwen/Qwen3-Coder-Next-FP8`, overridable via `--ai-model`

**Secrets:**
- [x] `pkg/secrets/validator.go` - AI false positive filter (`--ai-filter-secrets`)
  - Sends rule name, redacted value, and 8 lines of surrounding code to LLM
  - Returns `VERDICT: TRUE_POSITIVE or FALSE_POSITIVE`
  - Concurrent validation with semaphore (4 goroutines)

**SCA:**
- [x] `pkg/sca/reachability.go` - AI reachability analysis (`--ai-sca-reachability`)
  - Finds source files importing the vulnerable package (ecosystem-aware pattern matching: Go, Python, JS, Java, Ruby, Rust)
  - LLM returns `REACHABILITY: REACHABLE/UNREACHABLE/UNKNOWN`
  - UNREACHABLE findings downgraded one severity level and tagged `[Unreachable]`

**Terminal output:**
- [x] ANSI color output with TTY detection (no color when piped)
- [x] Wide character alignment (`runeWidth`, `visibleLen`) for correct emoji/CJK rendering in banners

### Phase 3 - Distribution (Partial — remaining items in Phase 11D)

- [x] **`go install`** - `go install github.com/Shasheen8/Broly/cmd/broly@latest` works when public (pure Go regex; Hyperscan via source build)
- [x] **Self-scan workflow** - `.github/workflows/scan.yml` — Broly scans itself on every PR and push to main
  - PR scan: SAST on changed files only + secrets + SCA on full repo
  - Posts formatted findings table as PR comment (updates in-place on re-runs)
  - Uploads SARIF to GitHub Security tab
  - Full scan on push to main / `workflow_dispatch`
  - `continue-on-error: true` — findings never block merges

*Remaining distribution tasks (proxy seeding, public repo, Homebrew, curl install, reusable workflow) moved to Phase 11D.*

### Phase 4 - Developer Experience (Complete - 2026-03-10)

- [x] **Config file** - `.broly.yaml` for project-level defaults; CLI flags override
- [x] **Baseline** - `.broly-baseline.yaml` suppress known FPs + require specific findings (missing = exit 1)
- [x] **Inline suppression** - `// broly:ignore` or `// broly:ignore <rule-id>` in source
- [x] **Deduplication** - fingerprint-based dedup in orchestrator post-processing pipeline
- [x] **Incremental scanning** - SHA256 hash cache skips unchanged files (`--incremental`)

### Phase 4.5 - Code Audit (Complete - 2026-03-10)

- [x] Removed dead code in `parser.go` (`_ = field`, unused `loc` variable)
- [x] Fixed `reachability.go` walk: now returns `filepath.SkipAll` after 5 files found instead of scanning entire tree
- [x] Fixed output file permissions: `0600` instead of world-readable `0666`
- [x] Stripped redundant/obvious comments across `parser.go`, `reachability.go`, `baseline.go`, `suppress.go`, `scanner.go`
- [x] Updated tagline and fixed release badge (static, shields.io requires public repo for dynamic)

### Phase 4.6 - Security Audit (Complete - 2026-03-12)

**P1 — Critical:**
- [x] **Credential exfiltration** - `validator.go` and `triage.go` were sending raw source lines (including unredacted secrets) to Together.ai. Fixed: `FileContextSafe` redacts the credential line; triage uses `f.Redacted` for secrets findings instead of file context
- [x] **Incremental caching on failure** - files were cached even when AI analysis errored, permanently hiding findings on future runs. Fixed: only successfully scanned files are cached; second blind WalkDir removed
- [x] **Baseline require runs after filtering** - required findings could be falsely reported missing if filtered by severity/rule/suppress. Fixed: `CheckRequired` now runs against the full deduplicated set before any filtering; `Suppress` runs last
- [x] **YAML severity parse failure** - `min_severity: low` in `.broly.yaml` silently failed because `Severity` had no YAML unmarshaler. Fixed: `UnmarshalYAML` added to `Severity`

**P2 — Significant:**
- [x] **SAST rule identity too coarse** - all HIGH findings shared the same rule ID (`broly.sast.ai.high`), collapsing distinct issues. Fixed: rule ID now uses a slugified issue description
- [x] **SCA severity hardcoded MEDIUM** - every OSV finding emitted as MEDIUM regardless of actual CVSS. Fixed: parses CVSS vector/score from OSV response; uses CIA impact heuristic for severity
- [x] **SAST fix stored in wrong field** - multi-line fixes written to `Advisory` (advisory_url) instead of `FixSuggestion`; continuation lines joined with spaces not newlines. Fixed both
- [x] **Table claims clean on baseline failure** - "Clean scan!" printed even when `MissingRequired` had entries. Fixed: clean message only shown when both findings and MissingRequired are empty

**P3 — Minor:**
- [x] **SAST 10 MB file limit** - sending 10 MB files to the model caused avoidable latency and cost. Reduced to 512 KB
- [x] **Secrets no skip list** - secrets scanner scanned vendor/node_modules/build dirs. Added `secretsSkipDirs` matching SAST's skip list
- [x] **`duration_ms` mislabeled** - `time.Duration` encodes as nanoseconds; JSON tag renamed to `duration_ns`
- [x] **Dead code removed** - `SCAScanner.scanPaths`, `parsedFinding.cvssVector`, `reachabilityResult.confidence`, `bannerLine`, unused `ScanMetrics` fields

### Phase 5 - AI Depth + Developer Feedback Loop (Complete - 2026-03-10)

The feedback loop is the feature that makes Broly self-improving. Every verdict a developer makes teaches the scanner what to ignore and what to catch — automatically, per repo, over time.

**AI Depth:**
- [x] **TP/FP verdict in PR comment** - AI labels each finding TRUE_POSITIVE or FALSE_POSITIVE before posting
- [x] **AI fix suggestions** - per-finding remediation code from LLM attached to PR comment; collapsible blocks in PR comment, inline in terminal for all scanner types
- [x] **Confidence scoring** - surfaced in output and PR comment per finding
- [x] **Explain mode** - `--explain` flag for concise attack-scenario sentence per finding

*Multi-file SAST (cross-file inter-procedural taint analysis) moved to Phase 11B.*

**Developer Feedback Loop (via CI/CD — no infra required):**
- [x] **Checkboxes in PR comment** - each finding has a [ ] checkbox; dev checks = false positive / accepted risk
- [x] **`feedback.yml` GitHub Action** - fires on `issue_comment` edit; verifies sender has write access before acting
- [x] **Auto-update `.broly-baseline.yaml`** - fingerprint written as suppress entry with reason and author; committed back to PR branch automatically
- [x] **Next scan is smarter** - baseline auto-loaded via `.broly.yaml`; known FPs never surface again
- [x] **Verdict history** - baseline file accumulates over time, becomes a repo-specific FP memory

```
  Dev checks checkbox in PR comment
          │
          ▼
  feedback.yml  GitHub Action
  reads checkbox state
          │
          ▼
  writes to .broly-baseline.yaml
  suppress:
    - fingerprint: abc123
      reason: "marked false positive by @dev on PR #42"
          │
          ▼
  committed back to repo (automated PR or direct push)
          │
          ▼
  next broly scan reads baseline
  finding suppressed — never surfaces again
```

### Phase 5.5 - Security Audit Round 2 (Complete - 2026-03-15)

**P1 — Critical:**
- [x] **Multiline secret exfiltration** - `FileContextSafe` only redacted `StartLine`, but multiline secrets (PEM keys, certs) span `StartLine` to `EndLine`. Remaining lines sent unredacted to Together.ai. Fixed: `FileContextSafe` now accepts `startLine, endLine` and redacts the entire range
- [x] **Incremental SAST caches false negatives** - `scanFile` returned `true` even when context was canceled mid-emit, permanently caching partially-scanned files. Fixed: returns `false` on `ctx.Done()` during finding emission

**P2 — Significant:**
- [x] **Fingerprint instability under `--no-redact`** - `ComputeFingerprint` hashed `Snippet`, which flips between redacted and raw content depending on `--no-redact`. Same secret got different fingerprints, breaking baseline suppressions. Fixed: secrets findings always hash `Redacted` value
- [x] **SAST fix extraction drops multiline fixes** - if the model emitted `Fix:` on its own line with code starting on the next line, continuation capture never started because `current.fix` was empty. Fixed: replaced `current.fix != ""` check with explicit `inFix` flag
- [x] **SCA CVSS still heuristic** - `cvssVectorSeverity` only checked C:H/I:H/A:H, ignoring scope change, attack vector, complexity. CVSSScore left at 0 for vector-based entries. Fixed: expanded heuristic (scope, two-high combos, AV/AC/PR) and returns approximate score

**P3 — Minor:**
- [x] **SAST table shows title instead of description** - DESCRIPTION column rendered `f.Title` instead of `f.Description`, hiding the AI-generated risk text. Fixed
- [x] **Fix/explain only rendered for SAST** - `printSecretsTable` and `printSCATable` showed verdict but silently dropped fix suggestions and explanations. Fixed: extracted `printVerdictAndFix` helper used by all three table printers
- [x] **README baseline field drift** - README showed `require.description` but struct uses `Reason`. Fixed
- [x] **Dead code removed** - `baseline.Apply` (superseded by `CheckRequired` + `Suppress`), `Finding.Advisory` (never populated), `parsedFinding.cvssVector` (parsed but unused)

### Phase 6 - Container Scanning

Three sub-phases, each independently shippable. Inspired by [Grype](https://github.com/anchore/grype) but leaner — reuses existing Broly infrastructure (OSV client, AI triage, baseline suppression) instead of building a standalone vuln DB.

**Reference:** Local Grype source at `~/Projects/app_sec_toolset/grype`

#### Phase 6A - Dockerfile Linting (Complete - 2026-03-18)

Same pattern as SAST — send the Dockerfile to the model, get security findings back. No new deps. Auto-detected during normal scans.

- [x] **Dockerfile detection** - `detectLangByName()` recognizes `Dockerfile`, `Dockerfile.*`, `Dockerfile-*`, `*.dockerfile`, `Containerfile`, and variants (case-insensitive)
- [x] **Docker Compose detection** - recognizes `docker-compose.yml`, `compose.yml`, `docker-compose.prod.yml`, and variants (`.yml`/`.yaml` only)
- [x] **Add to SAST language map** - Dockerfiles and Compose files flow through the existing SAST engine as `lang: "dockerfile"` / `lang: "docker-compose"`
- [x] **Dockerfile security prompt** - specialized prompt covering privilege escalation (root, SUID), secret exposure (ENV/ARG/build args), base image risks (unpinned tags, untrusted sources), dangerous instructions (ADD, curl|sh), multi-stage leaks, network exposure
- [x] **Docker Compose security prompt** - specialized prompt covering container escape (privileged, socket mounts, host PID/network), secret exposure in environment blocks, dangerous volume mounts, network exposure (0.0.0.0 bindings), resource limits
- [x] **Tests** - 28 test cases covering all filename patterns with correct positive and negative matches
- [x] **Rule IDs** - already handled by `slugify(p.issue)`, generates descriptive IDs like `broly.sast.ai.hardcoded_secrets_db_passwo`
- [x] **Auto-detection** - no flag needed, Dockerfiles and Compose files are picked up automatically during `broly scan`

#### Phase 6B - Image SBOM + Vuln Matching (Complete - 2026-03-21)

Lean approach: direct tar extraction + OS package parsing instead of Syft (avoids massive dependency). Covers Alpine and Debian/Ubuntu which represent the vast majority of container base images.

- [x] **`ScanTypeDockerfile`** - Dockerfile/Compose promoted out of SAST into own scan type; own section `▸ DOCKERFILE` in table, `broly.dockerfile.*` rule IDs
- [x] **`pkg/container/scanner.go`** - new scanner implementing `core.Scanner` with `ScanTypeContainer`
- [x] **Image pulling** - `google/go-containerregistry` for registry, tarball, and Docker daemon sources; socket check skips daemon when Docker not running
- [x] **Package extraction** - custom parsers in `packages.go`, no Syft dependency:
  - APK parser (`/lib/apk/db/installed`) for Alpine
  - DPKG parser (`/var/lib/dpkg/status`) for Debian/Ubuntu
  - Distro detection via `/etc/os-release`
  - Flattened filesystem via `mutate.Extract`
- [x] **OSV vuln matching** - direct `osvdev.QueryBatch()` in batches of 1000; CVSS scoring; ecosystem mapping (Alpine:v3.x, Debian:x, Ubuntu:x)
- [x] **Wire CLI** - `broly scan --container <image:tag>` or `--container <path.tar>`
- [x] **Output** - findings appear under `▸ CONTAINER` in table/JSON/SARIF with package name, version, fixed version, ecosystem
#### Phase 6C - Container Depth (Complete - 2026-03-26)

What Grype doesn't do — metadata enrichment, AI reasoning, and RPM support.

- [x] **Container-specific finding metadata** - `image_digest`, `layer_digest`, `base_image` fields on `Finding`; populated in JSON/SARIF output
- [x] **Layer attribution** - walks layers individually, diffs package lists between layers to attribute each package to the layer that introduced it; no longer flattens image
- [x] **Base vs application layer split** - `base-layer`/`app-layer` tags per finding based on layer index; LAYER column in container table shows `base` or `app`
- [x] **RPM support** - `rpmdb.sqlite` parser via pure-Go SQLite for RHEL 8+/Fedora 33+/CentOS/Rocky/Alma; ecosystem mapping to `Red Hat:X` and `Fedora:X`
- [x] **AI triage for container findings** - dedicated container prompt with CVE/package context instead of file context; asks for mitigation when no patch exists; SCA gets its own `buildSCAPrompt` (lockfile-focused, not container-focused)
- [x] **AI reachability for container findings** - folded into triage; the container triage prompt already reasons about whether the vulnerability is exploitable in typical container usage, making a separate reachability pass redundant for OS packages

#### Phase 6D - Container Language Packages (Complete - 2026-03-28)

Extract lockfiles from image layers, feed through osv-scalibr + OSV. No new deps — reuses SCA infrastructure entirely.

- [x] **Extract lockfiles from image layers** — scans each layer tar for 20+ lockfile names (requirements.txt, package-lock.json, yarn.lock, go.sum, Gemfile.lock, Cargo.lock, poetry.lock, pnpm-lock.yaml, composer.lock, etc.); 10MB size cap per file
- [x] **Write to temp dir + run SCA extractors** — extracted lockfiles written to temp dir with directory structure preserved; osv-scalibr `filesystem.Run()` with 9 ecosystem extractors
- [x] **Query OSV and emit findings** — batch query + CVSS parsing; emitted as `ScanTypeContainer` with language ecosystem tags (e.g. `PyPI`, `npm`, `Go`)
- [x] **Layer attribution** — each lockfile tracked to the layer that introduced it; findings tagged `base-layer`/`app-layer`
- [x] **Code cleanup** — consolidated `vulnToFinding` + `langVulnToFinding` into single `containerFinding()`; removed dead code; added `usr/lib/os-release` for Debian slim detection

### Phase 6E - Security Audit (Complete - 2026-03-28)

**P1 — Critical:**
- [x] **Path traversal in lockfile extraction** — tar header names were trusted without containment checks; malicious images could write outside the temp dir. Fixed: `filepath.Clean` + prefix containment + absolute path rejection
- [x] **Fingerprint collapses SCA/container findings** — `ComputeFingerprint` ignored package identity, deduplicating distinct vulns sharing the same advisory. Fixed: SCA/container fingerprints now use `type:ruleID:pkgName:pkgVersion:ecosystem`

**P2 — Significant:**
- [x] **Lockfile extraction ignores whiteouts** — OCI `.wh.*` deletion entries were not processed, causing deleted lockfiles to persist as false positives. Fixed: whiteout entries remove files from temp dir and previous layer results
- [x] **SCA findings triaged with container prompt** — `buildContainerPrompt` was applied to both `ScanTypeContainer` and `ScanTypeSCA`, skewing verdicts. Fixed: SCA gets dedicated `buildSCAPrompt` with lockfile-focused instructions
- [x] **SAST caches malformed LLM output** — `scanFile` returned success when LLM response was non-empty but unparsable. Fixed: returns false if response is non-empty, produced zero findings, and lacks NO_FINDINGS marker

**P3 — Minor:**
- [x] **Unbounded OSV batch queries** — SCA and container language scans sent one batch per target regardless of size. Fixed: both now batch at 1000, matching OS package scan
- [x] **Container stderr ignores --quiet** — progress output gated on `!s.quiet`; container added to scanner list in startup banner
- [x] **CVSS Vector wastes prompt tokens** — removed from SAST response format since parser never used it
- [x] **Dead code** — `SetRateLimit()` in `ai/client.go` had no callers; removed

### Phase 6F - Security Audit Round 2 (Complete - 2026-03-28)

**P1 — Critical:**
- [x] **Whiteout path traversal delete** — whiteout handler built `deletedPath` from untrusted tar names without containment; `../../.wh.somefile` could delete files outside temp dir. Fixed: moved `..`/abs rejection before whiteout handling + prefix containment check on delete path
- [x] **Fingerprint over-dedup across locations** — SCA/container fingerprints excluded `FilePath`, collapsing same vuln found in different lockfiles/targets into one finding. Fixed: added `FilePath` back to hash

**P2 — Significant:**
- [x] **Container OS query failures silent** — `scanOSPackages` swallowed OSV errors with a warning; scan appeared clean on network failure. Fixed: returns `error`, caller propagates
- [x] **Layer attribution wrong for multi-layer base images** — `layerIndex == 0` tagged only the first layer as base, but real base images span multiple layers. Fixed: tracks `baseBoundary` (last layer with OS package metadata); layers up to boundary tagged `base-layer`

**P3 — Minor:**
- [x] **Docker daemon serves stale images silently** — added stderr note when using local image: "run docker pull to update"
- [x] **SARIF emits image ref as raw URI** — container refs now use `container://` scheme instead of being emitted raw (which downstream tools could misparse as a URI scheme)

### Phase 7 - GitHub App (In Progress)

One-click org install. No per-repo workflow setup. Replaces `scan.yml` with a hosted webhook server that scans PRs and posts results back. No AWS dependency — runs standalone.

**Deps:** `google/go-github` (GitHub API), `bradleyfalzon/ghinstallation` (App auth)
**Hosting:** Fly.io, Cloud Run, or any HTTPS endpoint. Local dev via smee.io.

#### 7A - App Registration + Webhook Server (Complete - 2026-03-29)

- [x] **Register GitHub App** - "Broly Security Scanner" registered on Shasheen8 account; permissions: contents:read, pull_requests:write, checks:write, code scanning:write; subscribed to pull_request and push events
- [x] **`cmd/broly-app/main.go`** - HTTP server with `/webhook` and `/healthz` endpoints; HMAC-SHA256 signature verification; graceful shutdown
- [x] **App authentication** - JWT from private key via `ghinstallation.NewAppsTransportKeyFromFile`; per-installation token exchange for API + git clone
- [x] **Webhook handler** - routes `pull_request` (opened/synchronize), `push` (main/master only), and `installation` events
- [x] **Config** - env vars: `APP_ID`, `PRIVATE_KEY_PATH`, `WEBHOOK_SECRET`, `PORT` (default 8080)
- [x] **Local dev** - tested via smee.io webhook proxy; verified end-to-end event delivery

#### 7B - Scan Execution (Complete - 2026-03-29)

- [x] **Clone + scan** - shallow clone via git init + fetch + checkout at specific SHA; installation token for auth; temp dir with cleanup
- [x] **PR mode** - GitHub API lists changed files; SAST runs only on changed code files (cost control); secrets + SCA scan full repo
- [x] **Push mode** - gets changed files from commit via API; same filtering
- [x] **Changed-file filtering** - post-scan filter removes findings not in changed files; prevents historic repo noise on PRs
- [x] **AI triage enabled** - `--ai-triage` and `--explain` auto-enabled when `TOGETHER_API_KEY` is set
- [x] **Timeout** - 5 min per-scan timeout with context cancellation
- [x] **Concurrent scans** - semaphore-based limiter; default 4, configurable via `MAX_CONCURRENT_SCANS` env var; excess requests queue until a slot opens

#### 7C - Results Delivery (Complete - 2026-03-29)

- [x] **Check runs** - creates check run with pass/fail status; inline annotations on exact file:line with failure/warning/notice levels
- [x] **PR comments** - findings table with severity icons, verdict + confidence column, fix suggestions in collapsible blocks, false positive checkboxes with `<!-- fp:HASH -->` markers
- [x] **Update in-place** - detects existing `<!-- broly-scan -->` comment and updates instead of posting duplicate
- [x] **Broly footer** - branded footer with link
- [x] **CI workflow disabled** - `scan.yml` renamed to `.disabled`; app handles all PR scanning

#### 7D - Deployment (Partial - 2026-04-04)

- [x] **Dockerfile** - multi-stage build: `cgr.dev/chainguard/go:latest` builder → `cgr.dev/chainguard/git:latest` runtime; `CGO_ENABLED=0` static binary; non-root by default; includes git for repo cloning
- [x] **Structured JSON logging** - `log/slog` with JSON handler; every scan emits `repo`, `pr`, `sha`, `findings`, `duration_ms`; webhook events emit `event`, `delivery`

### Phase 8 - SBOM and License Detection (Next)

Full repo scan feature (not PR/push — runs on demand or scheduled). Generates a software bill of materials and detects license policy violations. Completes the compliance story.

#### 8A - SBOM Generation (Complete - 2026-04-01)

- [x] **CycloneDX output** - `broly sbom -f cyclonedx -o sbom.json` generates CycloneDX 1.5 JSON with serial number, tool metadata, PURLs per component
- [x] **SPDX output** - `broly sbom -f spdx -o sbom.spdx.json` generates SPDX 2.3 JSON with document namespace, creator info, external refs
- [x] **Package sources** - reuses osv-scalibr extractors across 19 ecosystems; deduplicates by name+version+ecosystem
- [x] **Metadata** - tool name, version, timestamp, PURLs (golang, pypi, npm, gem, cargo, maven, composer, nuget)
- [x] **Integration** - no new deps; `broly sbom` CLI command with `-f` and `-o` flags

#### 8B - License Detection (Complete - 2026-04-03)

- [x] **License extraction** - walks repo for LICENSE/LICENCE/COPYING files; identifies 13 license types by keyword matching (MIT, Apache-2.0, BSD-2/3, GPL-2/3, LGPL, AGPL, MPL-2.0, ISC, Unlicense, CC0, EPL)
- [x] **Policy engine** - `.broly.yaml` config: `allowed_licenses` (allowlist) and `denied_licenses` (denylist); denied = HIGH severity, unknown with allowlist = MEDIUM
- [x] **Findings** - `ScanTypeLicense` findings with fingerprints; only emitted when policy is configured
- [x] **Table output** - `▸ LICENSE` section in terminal; registered in orchestrator when policy present

#### 8C - Security Intelligence Layer (from sec-context research)

Integrates patterns from 150+ security research sources into the scan engine. Adds a deterministic regex layer, enriched AI prompts, hallucinated package detection, and priority scoring.

**Reference:** Local sec-context source at `~/Projects/app_sec_toolset/sec-context`

- [x] **Regex pre-filter** — 17 patterns covering secrets, SQL injection, command injection, XSS, weak crypto, path traversal, debug mode, CORS. Runs instantly per file before LLM. Findings tagged `prefilter` for distinction. Comment lines skipped.
- [x] **Enriched SAST prompts** — "Common AI Anti-Patterns" section added to code analysis prompt: 8 vulnerability classes the model should watch for, sourced from sec-context research
- [x] **Priority scoring** — `(Frequency × 2) + (Severity × 2) + Detectability` per finding via `ComputePriorityScore()`. Frequency based on vuln class (injection=9, secrets=8, crypto=6). Detectability: prefilter=8, AI=4. Available in JSON/SARIF.
*Hallucinated package detection moved to Phase 11B — needs registry API calls, not just OSV.*
- [x] **BAD/GOOD pattern pairs in triage** — 14 BAD/GOOD code pairs (SQL injection, command injection, XSS, hardcoded secrets, path traversal, weak hash, insecure deserialization, open redirect, debug mode, CORS, ECB mode, weak random, SSRF, XXE); matched by keyword from rule name + description; injected into SAST triage prompt before "Determine:" section

#### 8C.1 - Security Audit + Dependency Refresh (Complete - 2026-04-03)

- [x] **`strings.Title` deprecated** — replaced with `capitalize()` helper in `license/scanner.go`
- [x] **BAD/GOOD keyword mismatch** — keywords now match prefilter rule names exactly; removed overly broad terms that injected misleading examples for legitimate uses
- [x] **Prefilter `*` skip too broad** — `HasPrefix("*")` replaced with `trimmed == "*" || HasPrefix("* ")` to avoid skipping C pointer dereferences
- [x] **Path concatenation pattern narrowed** — bare `open()` now requires a string literal or path separator in arguments to reduce false positives
- [x] **SPDX document namespace** — `broly.dev` (unowned domain) replaced with `github.com/Shasheen8/Broly`
- [x] **`ComputePriorityScore` double loop** — two tag range loops merged into one
- [x] **Em-dashes restored** in triage prompt text
- [x] **osv-scalibr bumped to v0.4.5** — adds Perl/CPAN extractor, `.csproj` extractor, NuGet Central Package Management (`Directory.Packages.props`)
- [x] **Perl/CPAN ecosystem** — added to SCA and SBOM ecosystem lists; `pkg:cpan/` PURL added to SBOM formatter

#### 8D - IaC Scanning (Moved to Phase 11C)

*Terraform, CloudFormation, and Kubernetes manifest scanning moved to Phase 11C.*


### Phase 9 - Centralized Storage (Deferred — requires company AWS access)

Graduates the feedback loop from per-repo `.broly-baseline.yaml` to persistent org-wide storage. Verdicts from one repo inform scans across all repos. This is what makes Broly self-improving at scale.

**AWS resources needed:**
- S3 bucket (scan artifacts)
- DynamoDB table (findings index + verdicts)
- IAM role for the GitHub App / Broly service

#### 8A - Scan Artifact Storage (S3)

- [ ] **S3 bucket** - `broly-scans-{org}` with lifecycle policy (90 day retention, Glacier after 30)
- [ ] **Artifact writer** - after each scan, upload SARIF + JSON to `s3://{bucket}/{repo}/{sha}/{timestamp}.sarif`
- [ ] **Partition by repo/date** - enables per-repo audit trail and SIEM ingestion
- [ ] **Encryption** - SSE-S3 or SSE-KMS depending on compliance requirements
- [ ] **Access** - IAM role attached to the GitHub App service; no public access

#### 8B - Findings Index (DynamoDB)

- [ ] **Table design** - partition key: `repo#fingerprint`, sort key: `timestamp`
- [ ] **Finding record** - `{repo, fingerprint, rule_id, severity, verdict, who, when, pr_number, scan_sha}`
- [ ] **Verdict writer** - when a developer marks a finding as FP (checkbox in PR comment), write verdict to DynamoDB
- [ ] **Verdict reader** - at scan start, query DynamoDB for known FP fingerprints for this repo; feed into baseline suppress list before reporting
- [ ] **TTL** - auto-expire old findings after 1 year (configurable)
- [ ] **GSI** - `severity-index` for querying all criticals across the org; `repo-index` for per-repo views

#### 8C - Cross-Repo Learning

- [ ] **Org-wide FP suppression** - fingerprint marked FP in `payments-service` → query returns it when scanning `auth-service` → same pattern suppressed automatically
- [ ] **Confidence decay** - cross-repo suppressions get `MEDIUM` confidence (not `HIGH`); same-repo suppressions stay `HIGH`
- [ ] **Org-wide baseline** - shared suppress/require rules in DynamoDB, applied to all repos in addition to per-repo `.broly-baseline.yaml`
- [ ] **Metrics** - track FP rate per repo over time; measure how cross-repo learning reduces noise

#### 8D - Integration Points

- [ ] **GitHub App integration** - the app (Phase 7) reads/writes DynamoDB during scans
- [ ] **CLI integration** - `broly scan --org-baseline` flag pulls org-wide suppressions from DynamoDB
- [ ] **SIEM export** - S3 artifacts consumable by Splunk/Datadog/etc. via S3 event notifications or scheduled sync
- [ ] **Slack/Linear** - POST critical/high findings to Slack channel or auto-create Linear issues on scan completion

### Phase 10 - UI

- [ ] **Findings dashboard** - org-wide, filterable by repo/severity/scanner/status
- [ ] **Triage** - mark findings as accepted risk, false positive, assign to a developer
- [ ] **Baseline management** - manage suppress/require rules without editing YAML
- [ ] **Trend analysis** - findings over time, MTTR, severity breakdown

---

## 7. CLI Reference

```bash
# Full scan (all scanners)
broly scan .
broly scan /path/to/project

# Individual scanners
broly scan --secrets
broly scan --sca
broly scan --sast                                 # requires TOGETHER_API_KEY

# AI enhancements
broly scan --ai-filter-secrets                    # filter secrets false positives with AI
broly scan --ai-sca-reachability                  # check if vulnerable deps are actually called
broly scan --ai-model Qwen/Qwen3-Coder-Next-FP8   # override model (default)

# Output
broly scan -f json
broly scan -f sarif -o results.sarif
broly scan --min-severity high
broly scan --sca --offline                        # skip OSV API lookup

# Filtering
broly scan --exclude vendor,node_modules
broly scan --languages go,python,javascript       # limit SAST to specific languages
broly scan --workers 16

# Other
broly version
broly validate-rules
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan - no findings |
| 1 | Findings detected |
| 2 | Error (config, network, parse failure) |

---

## 8. Dependencies

### Current

| Dependency | Purpose | License |
|------------|---------|---------|
| `github.com/praetorian-inc/titus` | Secrets engine (487 rules, Hyperscan, live validation) | Apache 2.0 |
| `github.com/google/osv-scalibr` | Lockfile extraction (50+ formats) | Apache 2.0 |
| `osv.dev/bindings/go` | OSV API client (batch queries, retry) | Apache 2.0 |
| `github.com/ossf/osv-schema/bindings/go` | OSV vulnerability schema types | Apache 2.0 |
| `github.com/togethercomputer/together-go` | Together.ai Go SDK (AI SAST, Secrets FP filter, SCA reachability) | MIT |
| `github.com/spf13/cobra` | CLI framework | Apache 2.0 |

---

## 9. Supported Ecosystems

### Secrets (487 rules via Titus - NoseyParker + Kingfisher)

AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, Cloudflare, OpenAI, Anthropic,
Docker, npm, SSH/PGP/RSA/EC keys, database URIs, JWTs, generic tokens, and hundreds more.

### SCA (19 ecosystems, 50+ formats via osv-scalibr)

Go, Python (pip/poetry/pdm/uv/pipenv/conda), JavaScript (npm/yarn/pnpm/bun/deno), Ruby, Rust, Java (gradle/maven), PHP, .NET, Dart, C/C++ (Conan), Haskell, Elixir, Erlang, R, Swift, Lua, Nim, OCaml, Julia.

### SAST (AI - 18 languages, no rule files)

Go, Python, JavaScript, TypeScript, Java, Ruby, PHP, C#, Rust, C, C++, Kotlin, Swift, Bash, and more.

No rule files. No rule engine. No YAML. The model traces data flow from source to sink, infers CVSS scores, and pinpoints exact line numbers.

---

## 10. Live Rollout — 50 Core Prod Repos

### Stage 1: CI/CD Rollout (Achievable Now)

Pick the 50 highest-risk prod repos. Open one PR per repo adding `.github/workflows/broly.yml` and `.broly.yaml`. That's it — no new infrastructure, no approvals, no GitHub App.

**Week 1 — First scans run:**
```
PR opened on payments-service
  │
  ▼
broly scan  (git diff, changed files only)
  │
  ├── SECRETS:  no findings
  ├── SCA:      requests 2.28.0 → CVE-2023-32681  HIGH
  └── SAST:     SQL injection in user_lookup()     CRITICAL
  │
  ▼
PR Comment posted:

  ## Broly Security Scan — 2 findings

  | Severity   | Scanner | Rule              | File                  |
  |------------|---------|-------------------|-----------------------|
  | CRITICAL   | SAST    | SQL Injection      | api/handlers.py:42   |
  | HIGH       | SCA     | CVE-2023-32681    | requirements.txt      |

  [ ] CRITICAL · SQL Injection · api/handlers.py:42  (mark as false positive)
  [ ] HIGH     · CVE-2023-32681 · requirements.txt   (mark as false positive)
```

Dev looks at the SQL injection. It's real. Fixes it. Merges.
Dev looks at the CVE. The vulnerable function is never called. Checks the box.

**What happens next:**
```
Dev checks [ ] CVE-2023-32681
  │
  ▼
feedback.yml  fires
reads fingerprint from checkbox
  │
  ▼
.broly-baseline.yaml  updated automatically:

suppress:
  - fingerprint: "d4e8f2a1..."
    reason: "marked false positive by @dev — unreachable, PR #84"
  │
  ▼
committed back to payments-service repo
  │
  ▼
every future scan on payments-service
CVE-2023-32681 never surfaces again
```

---

**Week 4 — 50 repos active, pattern emerges:**

Across the 50 repos, the same 3 false positives keep appearing:
- A JWT validation pattern flagged as hardcoded secret (it's not)
- A known-safe SQL builder flagged as injection
- A test fixture flagged as leaked API key

Devs have already marked all three as FP across every repo that hit them.
Each repo's baseline file suppresses them silently on the next scan.

Signal-to-noise ratio: **week 1 = 40% FP rate. Week 4 = 8% FP rate.**

---

### Stage 2: GitHub App (Phase 7 — Iterate from here)

The 50-repo CI/CD rollout proved the tool works and the feedback loop is real.
Now roll it org-wide — 900 repos, one install, no per-repo PRs.

**What changes:**
```
Before (CI/CD):                     After (GitHub App):

50 repos, manual workflow PRs       900 repos, one org install
per-repo .broly-baseline.yaml       DynamoDB — org-wide verdict store
FP memory is per-repo               FP memory is cross-repo
dev marks FP in payments-service    same pattern suppressed in
→ still flags in auth-service         auth-service automatically
no central view                     central dashboard — all findings
                                      across all repos, one screen
```

**Cross-repo learning in action:**
```
payments-service  PR #84:
  dev marks JWT pattern as FP
  fingerprint d4e8f2a1 → FALSE_POSITIVE written to DynamoDB

auth-service  PR #91  (next day):
  same JWT pattern detected
  Broly queries DynamoDB before posting:
    "fingerprint d4e8f2a1 — marked FALSE_POSITIVE by @dev in payments-service"
  finding suppressed automatically
  dev never sees it

infra-service  PR #103:
  same pattern
  suppressed automatically
  not posted
```

After 6 months across 900 repos: the model has a verdict history that covers
every recurring FP in the org. New repos onboard clean — they inherit the
collective intelligence of every scan that came before.

---

### What This Looks Like at Month 6

| Metric                          | Week 1      | Month 6       |
|---------------------------------|-------------|---------------|
| Repos covered                   | 50          | 900           |
| FP rate                         | ~40%        | <5%           |
| Avg findings per PR             | 8           | 2-3 (signal only) |
| Dev time spent on FPs           | high        | near zero     |
| Org-wide FP patterns learned    | 0           | 100+          |
| Critical findings missed        | unknown     | tracked, trended |

## 11. Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Secrets scan | < 1s | Hyperscan engine |
| SCA scan (lockfile) | < 2s | osv.dev batch API |
| SAST scan (per file) | ~5-15s | Together.ai API latency, concurrent workers |
| Full scan (medium repo) | < 30s | All 3 scanners parallel |
| Binary size | < 15MB | No rule files embedded |

---

## 11. Build and Release

```bash
# Development
make build                     # build to bin/broly
make test                      # run tests
make validate-rules            # validate secret rules
make check                     # fmt + vet + test + validate

# Release
make release-snapshot          # local release build

# Install from source (macOS)
brew install vectorscan
git clone https://github.com/Shasheen8/Broly.git
cd Broly && make build
```

### GoReleaser targets

- `linux/amd64`, `linux/arm64` (pre-built binaries)
- `darwin/*` - build from source (CGO dependency on Vectorscan)

### Phase 11 - Remaining Work (Consolidated Backlog)

All pending items from earlier phases collected in one place.

#### 11A - GitHub App Completion

*(items from Phase 7C/7D)*

**SARIF upload to GitHub Security tab:**
- [ ] Add `uploadSARIF(ctx, client, req, result)` in `cmd/broly-app/results.go`
- [ ] Generate SARIF bytes using existing `pkg/report/sarif.go` formatter
- [ ] POST to `POST /repos/{owner}/{repo}/code-scanning/sarifs` (GitHub REST API) with base64-encoded gzip payload
- [ ] Call after `postCheckRun` in `scan.go` for both PR and push scans
- [ ] `security_events: write` permission already set in the GitHub App registration

**Deployment:**
- [ ] Pick a hosting platform — Fly.io for quick setup, ECS Fargate for production scale
- [ ] Write deploy config (`fly.toml` or ECS task definition + service + ALB)
- [ ] Set secrets in the platform (APP_ID, PRIVATE_KEY, WEBHOOK_SECRET, TOGETHER_API_KEY)
- [ ] Point the GitHub App webhook URL to the HTTPS endpoint
- [ ] Smoke test end-to-end with a real PR on a Togethercomputer repo

**Monitoring:**
- [ ] Wire `/healthz` to an uptime monitor (UptimeRobot free tier or platform-native health checks)
- [ ] Set up downtime alert (email or Slack)

#### 11B - AI Depth (Complete - 2026-04-08, PR #13)

*(items from Phase 5 and Phase 8C)*

- [x] **Slice-aware multi-file SAST** — repo index + import graph traversal (Go: same-package siblings + local module imports; JS/TS: relative imports); bounded by `--sast-slice-files` (default 2) and 16KB; finding attribution resolves back to correct file in slice; path containment enforced
- [x] **Package intelligence** — 5-state registry lookup model (exists/missing/private/transient/ambiguous); backends for npm, PyPI, crates.io; PyPI PEP 503 normalization; lookup cache per scan; conservative emission (all backends must report missing); `--package-intelligence` flag to opt in; `--package-registry-mode` + custom registry URLs for internal registries

#### 11C - IaC Scanning (Deferred)

*(items from Phase 8D)*

Deferred — AI-only approach has FP and bland-advice risk for IaC. Context matters too much (e.g. open port 443 vs 22, IAM * on read-only vs admin). Revisit with a deterministic-first approach (prefilter patterns for unambiguous misconfigs) when it becomes a priority.

- [ ] **Terraform** — misconfigurations in `.tf` files (open security groups, public S3, no encryption)
- [ ] **CloudFormation** — similar checks on CF templates
- [ ] **Kubernetes** — privileged pods, host networking, missing resource limits in manifests

#### 11D - Distribution (Complete - 2026-04-08)

*(items from Phase 3)*

- [x] **Make repo public** — unblocked `go install`, SARIF tab, reusable workflow
- [x] **Go proxy seeding** — `release.yml` hits `proxy.golang.org` + `sum.golang.org` after each tag; module path case-encoded (`!shasheen8/!broly`)
- [x] **GoReleaser wired** — `release.yml` now runs GoReleaser; `CGO_ENABLED=0` portable binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
- [x] **Reusable scan workflow** — `.github/workflows/broly-scan.yml`; users add one `uses:` line; supports `min_severity`, `scanners`, `ai_triage` inputs; posts PR comment + uploads SARIF
- [ ] **Homebrew tap** — skipped

---


### Phase 12 - Togethercomputer Org

Moving Broly under the Togethercomputer GitHub org. Broly becomes the internal security scanner for all Togethercomputer repos, powered by Together AI's own models.

**Pre-requisites before org push:**
- [ ] 11A complete (SARIF upload + deployed endpoint)
- [ ] broly-app running and tested end-to-end on at least one repo

**Repo migration:**
- [ ] Fork/transfer to `togethercomputer/broly`
- [ ] Update module path in `go.mod`: `github.com/togethercomputer/broly`
- [ ] Update all internal import paths across the codebase (`sed` or `gofmt` tooling)
- [ ] Update README badges, links, and Go install path to point to new org
- [ ] Tag a clean release from the org repo

**GitHub App (org-level):**
- [ ] Register a new GitHub App under the Togethercomputer org
- [ ] Install on all repos (or a selected subset to start)
- [ ] Deploy broly-app to a production endpoint with Togethercomputer infrastructure
- [ ] Update webhook URL in the new GitHub App settings
- [ ] Smoke test with a real PR on a Togethercomputer repo

**Config:**
- [ ] Confirm default model or update `defaultModel` in `pkg/sast/engine.go`
- [ ] Set `TOGETHER_API_KEY` in the deployment environment
