package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/chain"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/iac"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/scanignore"
	"github.com/Shasheen8/Broly/pkg/secrets"
	"github.com/Shasheen8/Broly/pkg/workflow"
)

func (a *App) scanPR(ctx context.Context, client *github.Client, req scanRequest) {
	a.scanSem <- struct{}{}
	defer func() { <-a.scanSem }()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	repo := req.owner + "/" + req.repo
	slog.Info("scan started", "event", "pull_request", "repo", repo, "pr", req.prNumber, "sha", req.headSHA)

	// Clone the repo at the PR head SHA.
	dir, cleanup, err := cloneRepo(ctx, client, req)
	if err != nil {
		slog.Error("clone failed", "repo", repo, "pr", req.prNumber, "err", err)
		postCheckRunError(ctx, client, req, fmt.Sprintf("Clone failed: %v", err))
		return
	}
	defer cleanup()

	// Get changed files for cost-controlled SAST.
	changed := getChangedFiles(ctx, client, req)

	// Run scan.
	result, err := runBrolyScan(ctx, dir, changed)
	if err != nil {
		slog.Error("scan failed", "repo", repo, "pr", req.prNumber, "err", err)
		postCheckRunError(ctx, client, req, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	stripPrefix(result, dir)

	// Filter to only findings in files changed by this PR.
	if len(changed) > 0 {
		result.Findings = filterToChangedFiles(result.Findings, changed)
	}

	slog.Info("scan complete",
		"event", "pull_request",
		"repo", repo,
		"pr", req.prNumber,
		"sha", req.headSHA,
		"findings", len(result.Findings),
		"duration_ms", result.Duration.Milliseconds(),
	)

	postCheckRun(ctx, client, req, result)
	postPRComment(ctx, client, req, result)
}

func (a *App) scanPush(ctx context.Context, client *github.Client, req scanRequest) {
	a.scanSem <- struct{}{}
	defer func() { <-a.scanSem }()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	repo := req.owner + "/" + req.repo
	slog.Info("scan started", "event", "push", "repo", repo, "sha", req.headSHA)

	dir, cleanup, err := cloneRepo(ctx, client, req)
	if err != nil {
		slog.Error("clone failed", "repo", repo, "sha", req.headSHA, "err", err)
		return
	}
	defer cleanup()

	changed := getCommitFiles(ctx, client, req)

	result, err := runBrolyScan(ctx, dir, changed)
	if err != nil {
		slog.Error("scan failed", "repo", repo, "sha", req.headSHA, "err", err)
		return
	}

	stripPrefix(result, dir)

	if len(changed) > 0 {
		result.Findings = filterToChangedFiles(result.Findings, changed)
	}

	slog.Info("scan complete",
		"event", "push",
		"repo", repo,
		"sha", req.headSHA,
		"findings", len(result.Findings),
		"duration_ms", result.Duration.Milliseconds(),
	)
}

// validGitSHAPattern matches a full or abbreviated git commit SHA (hex
// only). Rejecting anything else before it reaches exec.Command closes off
// git's argument-injection surface (e.g. a ref string starting with "-"
// being parsed as a flag like --upload-pack=<command>).
var validGitSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// cloneRepo does a shallow clone at the given SHA using the installation token.
func cloneRepo(ctx context.Context, client *github.Client, req scanRequest) (string, func(), error) {
	if !validGitSHAPattern.MatchString(req.headSHA) {
		return "", nil, fmt.Errorf("invalid head SHA %q", req.headSHA)
	}

	dir, err := os.MkdirTemp("", "broly-scan-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	// Get installation token for authenticated clone.
	token, err := installationToken(ctx, client)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("get token: %w", err)
	}

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, req.owner, req.repo)
	redactToken := func(out []byte) string {
		return redactSecret(out, token)
	}

	// Shallow clone at a specific SHA: git init + fetch + checkout (--branch doesn't accept SHAs).
	cmd := exec.CommandContext(ctx, "git", "init", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git init: %s: %w", redactToken(out), err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "remote", "add", "origin", cloneURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git remote add: %s: %w", redactToken(out), err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "fetch", "--depth=1", "origin", req.headSHA)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git fetch: %s: %w", redactToken(out), err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "checkout", "FETCH_HEAD")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git checkout: %s: %w", redactToken(out), err)
	}

	return dir, cleanup, nil
}

func redactSecret(out []byte, secret string) string {
	if secret == "" {
		return string(out)
	}
	return strings.ReplaceAll(string(out), secret, "REDACTED")
}

func installationToken(ctx context.Context, client *github.Client) (string, error) {
	transport, ok := client.Client().Transport.(*ghinstallation.Transport)
	if !ok {
		return "", fmt.Errorf("could not extract installation token from transport")
	}
	return transport.Token(ctx)
}

// codeExts is the set of file extensions SAST will scan.
var codeExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".rb": true, ".php": true, ".cs": true, ".rs": true,
	".c": true, ".cpp": true, ".h": true, ".hpp": true, ".kt": true,
	".swift": true, ".sh": true, ".bash": true,
	// IaC + workflow files for changed-file filtering.
	".tf": true, ".yaml": true, ".yml": true, ".json": true,
}

// isScannablePath returns true for code files plus workflow/IaC definition paths.
func isScannablePath(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if codeExts[ext] {
		return true
	}
	base := strings.ToLower(filepath.Base(filename))
	switch base {
	case "action.yml", "action.yaml", "chart.yaml", "chart.yml",
		"values.yaml", "values.yml", "Dockerfile", "Makefile":
		return true
	}
	return strings.Contains(strings.ToLower(filename), ".github/workflows/")
}

// getChangedFiles returns the list of code files changed in a PR.
func getChangedFiles(ctx context.Context, client *github.Client, req scanRequest) []string {
	if req.prNumber == 0 {
		return nil
	}

	opts := &github.ListOptions{PerPage: 100}
	var changed []string
	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, req.owner, req.repo, req.prNumber, opts)
		if err != nil {
			slog.Error("list PR files", "err", err)
			return changed
		}
		for _, f := range files {
			fn := f.GetFilename()
			if isScannablePath(fn) && !scanignore.PathHasIgnoredDir(fn) {
				changed = append(changed, fn)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return changed
}

func cleanRepoRelativePath(rel string) (string, error) {
	cleanRel := filepath.Clean(rel)
	if cleanRel == "." || filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) || cleanRel == ".." {
		return "", fmt.Errorf("changed path escapes repo: %s", rel)
	}
	return cleanRel, nil
}

func validateRepoPathTarget(dir, rel string) error {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	fullPath := filepath.Join(dir, rel)
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil {
		return err
	}
	if relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("changed path resolves outside repo: %s", rel)
	}
	return nil
}

// runBrolyScan runs the Broly orchestrator on the given directory.
// If changedFiles is non-nil, SAST is limited to those files.
func runBrolyScan(ctx context.Context, dir string, changedFiles []string) (*core.ScanResult, error) {
	hasAI := os.Getenv("TOGETHER_API_KEY") != ""

	cfg := &core.Config{
		Targets:       []string{dir},
		EnableSecrets: true,
		EnableSCA:     true,
		AITriage:      hasAI,
		Adversarial:   hasAI,
		ExploitChains: false, // chains run on combined findings below
		Explain:       hasAI,
		Workers:       4,
		Quiet:         true,
	}

	// Only register workflow/IaC scanners when relevant files exist.
	if workflow.ZizmorAvailable() && (len(changedFiles) == 0 || workflow.TouchesWorkflowDefinitions(changedFiles)) {
		cfg.EnableWorkflow = true
	}
	if iac.CheckovAvailable() && (len(changedFiles) == 0 || iac.TouchesIaCDefinitions(changedFiles)) {
		cfg.EnableIaC = true
	}
	if sca.DepxAvailable() {
		cfg.SupplyChain = true
	}

	orch := orchestrator.New(cfg)
	orch.Register(secrets.NewSecretsScanner())
	orch.Register(sca.NewSCAScanner())
	if cfg.EnableWorkflow {
		orch.Register(workflow.NewWorkflowScanner())
	}
	if cfg.EnableIaC {
		orch.Register(iac.NewIaCScanner())
	}

	start := time.Now()
	result, err := orch.Run(ctx)
	if err != nil {
		return nil, err
	}

	// SAST: scan only changed files (or full repo if no diff).
	if hasAI {
		sastTargets := []string{dir}
		if len(changedFiles) > 0 {
			sastTargets = make([]string, 0, len(changedFiles))
			for _, f := range changedFiles {
				cleanRel, err := cleanRepoRelativePath(f)
				if err != nil {
					slog.Warn("changed path escapes repo", "path", f, "err", err)
					continue
				}
				if err := validateRepoPathTarget(dir, cleanRel); err != nil {
					slog.Warn("changed path resolves outside repo", "path", f, "err", err)
					continue
				}
				sastTargets = append(sastTargets, filepath.Join(dir, cleanRel))
			}
		}
		sastCfg := &core.Config{
			Targets:       sastTargets,
			EnableSAST:    true,
			AITriage:      true,
			Adversarial:   true,
			ExploitChains: false,
			Explain:       true,
			Workers:       4,
			Quiet:         true,
		}
		sastOrch := orchestrator.New(sastCfg)
		sastOrch.Register(sast.NewSASTScanner())
		sastResult, err := sastOrch.Run(ctx)
		if err == nil {
			result.Findings = append(result.Findings, sastResult.Findings...)
		}
	}

	// Exploit chains: link cross-scanner true positives on the combined set.
	if hasAI && chain.Eligible(result.Findings) {
		client, ok := ai.New(ai.DefaultModel)
		if ok {
			chainCtx, chainCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer chainCancel()
			chains, findings := chain.BuildExploitChains(chainCtx, client, result.Findings)
			result.Findings = findings
			result.ExploitChains = chains
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// getCommitFiles returns the list of code files changed in a push commit.
func getCommitFiles(ctx context.Context, client *github.Client, req scanRequest) []string {
	if req.headSHA == "" {
		return nil
	}

	commit, _, err := client.Repositories.GetCommit(ctx, req.owner, req.repo, req.headSHA, nil)
	if err != nil {
		slog.Error("get commit files", "err", err)
		return nil
	}

	var changed []string
	for _, f := range commit.Files {
		fn := f.GetFilename()
		if isScannablePath(fn) && !scanignore.PathHasIgnoredDir(fn) {
			changed = append(changed, fn)
		}
	}
	return changed
}

// filterToChangedFiles keeps only findings whose FilePath matches a changed file.
func filterToChangedFiles(findings []core.Finding, changed []string) []core.Finding {
	changedSet := make(map[string]bool, len(changed))
	for _, f := range changed {
		changedSet[f] = true
	}

	var filtered []core.Finding
	for _, f := range findings {
		if changedSet[f.FilePath] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func stripPrefix(result *core.ScanResult, dir string) {
	prefix := dir + "/"
	for i := range result.Findings {
		original := result.Findings[i].FilePath
		result.Findings[i].FilePath = strings.TrimPrefix(result.Findings[i].FilePath, prefix)
		if result.Findings[i].FilePath != original {
			result.Findings[i].ComputeIdentityKeys()
		}
	}
}
