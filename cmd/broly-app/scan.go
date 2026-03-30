package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/secrets"
)

func (a *App) scanPR(ctx context.Context, client *github.Client, req scanRequest) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("scanning PR #%d on %s/%s at %s", req.prNumber, req.owner, req.repo, req.headSHA)

	// Clone the repo at the PR head SHA.
	dir, cleanup, err := cloneRepo(ctx, client, req)
	if err != nil {
		log.Printf("clone failed: %v", err)
		return
	}
	defer cleanup()

	// Get changed files for cost-controlled SAST.
	changed := getChangedFiles(ctx, client, req)

	// Run scan.
	result, err := runBrolyScan(ctx, dir, changed)
	if err != nil {
		log.Printf("scan failed on %s/%s PR #%d: %v", req.owner, req.repo, req.prNumber, err)
		return
	}

	stripPrefix(result, dir)

	// Filter to only findings in files changed by this PR.
	if len(changed) > 0 {
		result.Findings = filterToChangedFiles(result.Findings, changed)
	}

	log.Printf("PR #%d on %s/%s: %d findings (in changed files)", req.prNumber, req.owner, req.repo, len(result.Findings))

	postCheckRun(ctx, client, req, result)
	postPRComment(ctx, client, req, result)
}

func (a *App) scanPush(ctx context.Context, client *github.Client, req scanRequest) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("scanning push on %s/%s at %s", req.owner, req.repo, req.headSHA)

	dir, cleanup, err := cloneRepo(ctx, client, req)
	if err != nil {
		log.Printf("clone failed: %v", err)
		return
	}
	defer cleanup()

	changed := getCommitFiles(ctx, client, req)

	result, err := runBrolyScan(ctx, dir, changed)
	if err != nil {
		log.Printf("scan failed on %s/%s push %s: %v", req.owner, req.repo, req.headSHA, err)
		return
	}

	stripPrefix(result, dir)

	if len(changed) > 0 {
		result.Findings = filterToChangedFiles(result.Findings, changed)
	}

	log.Printf("push on %s/%s: %d findings (in changed files)", req.owner, req.repo, len(result.Findings))
}

// cloneRepo does a shallow clone at the given SHA using the installation token.
func cloneRepo(ctx context.Context, client *github.Client, req scanRequest) (string, func(), error) {
	dir, err := os.MkdirTemp("", "broly-scan-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	// Get installation token for authenticated clone.
	token, err := installationToken(client)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("get token: %w", err)
	}

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, req.owner, req.repo)

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--branch", req.headSHA, cloneURL, dir)
	cmd.Stderr = os.Stderr

	// --branch doesn't work with SHAs on shallow clone. Use fetch instead.
	cmd = exec.CommandContext(ctx, "git", "init", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git init: %s: %w", out, err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "remote", "add", "origin", cloneURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git remote add: %s: %w", out, err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "fetch", "--depth=1", "origin", req.headSHA)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git fetch: %s: %w", out, err)
	}

	cmd = exec.CommandContext(ctx, "git", "-C", dir, "checkout", "FETCH_HEAD")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git checkout: %s: %w", out, err)
	}

	return dir, cleanup, nil
}

func installationToken(client *github.Client) (string, error) {
	transport, ok := client.Client().Transport.(*ghinstallation.Transport)
	if !ok {
		return "", fmt.Errorf("could not extract installation token from transport")
	}
	return transport.Token(context.Background())
}

// getChangedFiles returns the list of code files changed in a PR.
func getChangedFiles(ctx context.Context, client *github.Client, req scanRequest) []string {
	if req.prNumber == 0 {
		return nil
	}

	opts := &github.ListOptions{PerPage: 100}
	files, _, err := client.PullRequests.ListFiles(ctx, req.owner, req.repo, req.prNumber, opts)
	if err != nil {
		log.Printf("list PR files: %v", err)
		return nil
	}

	codeExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".cs": true, ".rs": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true, ".kt": true,
		".swift": true, ".sh": true, ".bash": true,
	}

	var changed []string
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f.GetFilename()))
		if codeExts[ext] {
			changed = append(changed, f.GetFilename())
		}
	}
	return changed
}

// runBrolyScan runs the Broly orchestrator on the given directory.
// If changedFiles is non-nil, SAST is limited to those files.
func runBrolyScan(ctx context.Context, dir string, changedFiles []string) (*core.ScanResult, error) {
	hasAI := os.Getenv("TOGETHER_API_KEY") != ""

	// Secrets + SCA: scan full repo.
	cfg := &core.Config{
		Targets:       []string{dir},
		EnableSecrets: true,
		EnableSCA:     true,
		AITriage:      hasAI,
		Explain:       hasAI,
		Workers:       4,
		Quiet:         true,
	}

	orch := orchestrator.New(cfg)
	orch.Register(secrets.NewSecretsScanner())
	orch.Register(sca.NewSCAScanner())

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
				sastTargets = append(sastTargets, filepath.Join(dir, f))
			}
		}
		sastCfg := &core.Config{
			Targets:    sastTargets,
			EnableSAST: true,
			AITriage:   true,
			Explain:    true,
			Workers:    4,
			Quiet:      true,
		}
		sastOrch := orchestrator.New(sastCfg)
		sastOrch.Register(sast.NewSASTScanner())
		sastResult, err := sastOrch.Run(ctx)
		if err == nil {
			result.Findings = append(result.Findings, sastResult.Findings...)
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
		log.Printf("get commit files: %v", err)
		return nil
	}

	codeExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".cs": true, ".rs": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true, ".kt": true,
		".swift": true, ".sh": true, ".bash": true,
	}

	var changed []string
	for _, f := range commit.Files {
		ext := strings.ToLower(filepath.Ext(f.GetFilename()))
		if codeExts[ext] {
			changed = append(changed, f.GetFilename())
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
		if strings.HasPrefix(result.Findings[i].FilePath, prefix) {
			result.Findings[i].FilePath = strings.TrimPrefix(result.Findings[i].FilePath, prefix)
		}
	}
}
