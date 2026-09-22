# Using Broly

Broly is a CLI-first code security scanner: secrets, SCA, SAST, workflow, IaC, containers, SBOM, and supply chain auditing in one Go binary, powered by Together AI for SAST and triage. Watch it run first, then install it and see every flag.

## Broly in action

<!-- video: Broly.mp4 -->

## Install

```bash
go install github.com/Shasheen8/Broly/cmd/broly@latest
export TOGETHER_API_KEY=your_key_here
```

SAST, AI triage, adversarial verification, and exploit chains need the Together AI key. Everything else runs without it.

## Scanners and commands

The full `broly --help` output, for reference:

```
Broly is a CLI-first berserker code security scanner.

SCANNERS
  secrets        487 Titus rules, Hyperscan locally (Go regex in CI)
  sca            osv-scalibr + osv.dev, 20 ecosystems
  sast           Together AI LLM, 17 regex prefilter patterns
  workflow       zizmor for GitHub Actions static analysis
  iac            checkov for Terraform, Kubernetes, Helm, CloudFormation
  supply-chain   depx for known-malicious package detection
  container      go-containerregistry + osv.dev
  license        File-based detection, 13 license types
  sbom           CycloneDX 1.5 or SPDX 2.3

VULNERABILITY CLASSES (SAST detects via LLM + regex prefilter)
  SQL Injection (CWE-89)              --sqli
  Cross-Site Scripting (CWE-79/80)   --xss
  Command Injection / RCE (CWE-78)    --rce
  Server-Side Request Forgery (CWE-918)  --ssrf
  XML External Entity (CWE-611)      --xxe
  IDOR (CWE-639/862/863)              --idor
  BOLA (CWE-639/862/863)              --bola
  Path Traversal (CWE-22/23/73)      --path-traversal
  Insecure Deserialization (CWE-502) --deserialization
  Open Redirect (CWE-601)            --open-redirect
  Weak Cryptography (CWE-327/328)    --weak-crypto
  Hardcoded Secrets (CWE-798/321)    --hardcoded-secret

AI FEATURES (require TOGETHER_API_KEY)
  --ai-triage              Verdict (TP/FP) + fix suggestion per finding
  --ai-triage --explain    + attack scenario per finding
  --adversarial            Adversarial verify on critical SAST/IaC TPs
  --exploit-chains         Link critical cross-scanner TPs into attack narratives
  --ai-filter-secrets      Filter secrets false positives with AI
  --ai-sca-reachability    Check if vulnerable deps are actually called
  --package-intelligence   Detect hallucinated/non-existent packages

VULN CLASS FOCUS (narrow SAST to a specific vulnerability class)
  --sqli --xss --rce --ssrf --xxe --idor --bola --path-traversal
  --deserialization --open-redirect --weak-crypto --hardcoded-secret
  Each flag focuses the LLM on one class with tailored detection guidance.
  Multiple flags can be combined to focus on several classes at once.

QUICK START
  broly scan                              # secrets + SCA + SAST
  broly scan . --sast --ai-triage         # SAST with AI triage
  broly scan . --workflow --iac            # IaC + workflow scanning
  broly scan . --supply-chain             # malicious package audit
  broly scan . --sqli --ai-triage         # focus on SQL injection only
  broly scan . --ai-triage --adversarial  # full adversarial pipeline
  broly scan . -f sarif -o results.sarif   # SARIF for GitHub Security tab
  broly scan . --container python:3.12    # scan a container image
  broly scan . --auto-containers          # scan Dockerfile base images
  broly sbom -f cyclonedx -o sbom.json    # generate CycloneDX SBOM
  broly changelog generate --write        # AI-draft a changelog entry
  broly update                            # update to latest version

CONFIGURATION
  broly reads .broly.yaml from the repo root automatically.
  CLI flags always override config file values.

  .broly.yaml example:
    min_severity: low
    exclude_paths: [vendor, .git]
    workers: 8
    enable_workflow: true
    enable_iac: true
    supply_chain: true
    vuln_classes: [sqli, xss]           # focus SAST on specific classes

ENVIRONMENT VARIABLES
  TOGETHER_API_KEY     Required for SAST, AI triage, adversarial, exploit chains
  GITHUB_TOKEN         Used by secrets validation (--validate) and SCA reachability
  DEPX_HOME            Override depx cache directory (default: $HOME/.cache/depx)

EXIT CODES
  0   No findings (clean scan)
  1   Findings detected (or required baseline missing): signals CI to fail
  2   Operational error (bad flags, scan failure, missing tool)

TOOL AUTO-INSTALL
  zizmor and checkov auto-install into ~/.cache/broly/venv/ on first use.
  depx must be installed manually: https://github.com/projectdiscovery/depx

Built in Go for speed. Designed for local developer runs and CI.
```
