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
	"github.com/Shasheen8/Broly/pkg/container"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/iac"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/prdiff"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/scanignore"
	"github.com/Shasheen8/Broly/pkg/secrets"
	"github.com/Shasheen8/Broly/pkg/triage"
	"github.com/Shasheen8/Broly/pkg/workflow"
)

const (
	scanTimeout        = 10 * time.Minute
	triageTimeout      = 15 * time.Minute
	adversarialTimeout = 10 * time.Minute
	chainTimeout       = 5 * time.Minute
)

// baseImageAdvisoryRuleID marks the synthetic advisory for a changed Dockerfile
// FROM. It carries a PackageName/Version but is not a real package finding.
const baseImageAdvisoryRuleID = "broly.container.base_image_advisory"

func (a *App) scanPR(ctx context.Context, client *github.Client, req scanRequest) {
	a.scanSem <- struct{}{}
	defer func() { <-a.scanSem }()

	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	repo := req.owner + "/" + req.repo
	slog.Info("scan started", "event", "pull_request", "repo", repo, "pr", req.prNumber, "sha", req.headSHA)

	// Clone the repo at the PR head SHA.
	dir, cleanup, err := cloneRepo(scanCtx, client, req)
	if err != nil {
		slog.Error("clone failed", "repo", repo, "pr", req.prNumber, "err", err)
		postCheckRunError(scanCtx, client, req, fmt.Sprintf("Clone failed: %v", err))
		return
	}
	defer cleanup()

	// Changed files + per-file added-line maps for diff scoping.
	changed, diffs := getChangedFiles(scanCtx, client, req)

	// Base-branch FROM images, so only PR-changed base images get advisories.
	baseImages := baseBranchDockerfileImages(scanCtx, client, req, changed)

	// Run scan (triage is deferred until after diff scoping so LLM budget is
	// only spent on findings the PR actually introduced).
	result, err := runBrolyScan(scanCtx, dir, changed)
	if err != nil {
		slog.Error("scan failed", "repo", repo, "pr", req.prNumber, "err", err)
		postCheckRunError(scanCtx, client, req, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	stripPrefix(result, dir)

	// Base-image advisories instead of pulling images: OS package vulns come
	// from the distro and are fixed by changing base, and SCA covers the rest.
	for _, ic := range changedDockerfileImages(dir, changed, baseImages) {
		result.Findings = append(result.Findings, baseImageAdvisoryFinding(ic))
	}

	// Scope findings to the PR diff: line-level for code findings, file-level
	// for package findings.
	if len(changed) > 0 {
		result.Findings = filterToPRDiffScope(result.Findings, changed, diffs)
	}

	// AI triage + adversarial verification on the diff-scoped set only.
	result.Findings = triageFindings(dir, result.Findings)

	// Exploit chains link cross-scanner true positives.
	if chain.Eligible(result.Findings) {
		chainCtx, chainCancel := context.WithTimeout(context.Background(), chainTimeout)
		chains, chainedFindings := buildExploitChains(chainCtx, result.Findings)
		chainCancel()
		result.Findings = chainedFindings
		result.ExploitChains = chains
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

	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	repo := req.owner + "/" + req.repo
	slog.Info("scan started", "event", "push", "repo", repo, "sha", req.headSHA)

	dir, cleanup, err := cloneRepo(scanCtx, client, req)
	if err != nil {
		slog.Error("clone failed", "repo", repo, "sha", req.headSHA, "err", err)
		postCheckRunError(scanCtx, client, req, fmt.Sprintf("Clone failed: %v", err))
		return
	}
	defer cleanup()

	changed, diffs := getCommitFiles(scanCtx, client, req)

	result, err := runBrolyScan(scanCtx, dir, changed)
	if err != nil {
		slog.Error("scan failed", "repo", repo, "sha", req.headSHA, "err", err)
		postCheckRunError(scanCtx, client, req, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	stripPrefix(result, dir)

	// No base branch for pushes: every FROM in a changed container spec gets
	// an advisory.
	for _, ic := range changedDockerfileImages(dir, changed, nil) {
		result.Findings = append(result.Findings, baseImageAdvisoryFinding(ic))
	}

	if len(changed) > 0 {
		result.Findings = filterToPRDiffScope(result.Findings, changed, diffs)
	}

	result.Findings = triageFindings(dir, result.Findings)

	if chain.Eligible(result.Findings) {
		chainCtx, chainCancel := context.WithTimeout(context.Background(), chainTimeout)
		chains, chainedFindings := buildExploitChains(chainCtx, result.Findings)
		chainCancel()
		result.Findings = chainedFindings
		result.ExploitChains = chains
	}

	slog.Info("scan complete",
		"event", "push",
		"repo", repo,
		"sha", req.headSHA,
		"findings", len(result.Findings),
		"duration_ms", result.Duration.Milliseconds(),
	)

	postCheckRun(ctx, client, req, result)
}

// triageFindings runs AI triage and adversarial verification on the given
// findings. Dedicated background contexts are used so a long scan cannot
// starve triage of its time budget.
func triageFindings(cloneDir string, findings []core.Finding) []core.Finding {
	if len(findings) == 0 || os.Getenv("TOGETHER_API_KEY") == "" {
		return findings
	}
	t := triage.New("", true, cloneDir)
	if t == nil {
		return findings
	}
	triageCtx, triageCancel := context.WithTimeout(context.Background(), triageTimeout)
	defer triageCancel()
	out := t.Run(triageCtx, findings)

	advCtx, advCancel := context.WithTimeout(context.Background(), adversarialTimeout)
	defer advCancel()
	return t.RunAdversarial(advCtx, out)
}

func buildExploitChains(ctx context.Context, findings []core.Finding) ([]core.ExploitChain, []core.Finding) {
	client, ok := ai.New(ai.DefaultModel)
	if !ok {
		return nil, findings
	}
	return chain.BuildExploitChains(ctx, client, findings)
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

// getChangedFiles returns the files changed in a PR plus per-file added-line
// maps parsed from GitHub's patch field. All non-ignored files are included
// (not just code files) so secrets in config/dotfiles stay in scope.
func getChangedFiles(ctx context.Context, client *github.Client, req scanRequest) ([]string, map[string]*prdiff.FileDiff) {
	if req.prNumber == 0 {
		return nil, nil
	}

	opts := &github.ListOptions{PerPage: 100}
	var changed []string
	diffs := make(map[string]*prdiff.FileDiff)
	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, req.owner, req.repo, req.prNumber, opts)
		if err != nil {
			slog.Error("list PR files", "err", err)
			return changed, diffs
		}
		for _, f := range files {
			fn := f.GetFilename()
			if fn == "" || scanignore.PathHasIgnoredDir(fn) {
				continue
			}
			changed = append(changed, fn)
			if patch := f.GetPatch(); patch != "" {
				diffs[fn] = prdiff.ParsePatch(patch)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return changed, diffs
}

// getCommitFiles returns the files changed in a push commit plus per-file
// added-line maps.
func getCommitFiles(ctx context.Context, client *github.Client, req scanRequest) ([]string, map[string]*prdiff.FileDiff) {
	if req.headSHA == "" {
		return nil, nil
	}

	commit, _, err := client.Repositories.GetCommit(ctx, req.owner, req.repo, req.headSHA, nil)
	if err != nil {
		slog.Error("get commit files", "err", err)
		return nil, nil
	}

	var changed []string
	diffs := make(map[string]*prdiff.FileDiff)
	for _, f := range commit.Files {
		fn := f.GetFilename()
		if fn == "" || scanignore.PathHasIgnoredDir(fn) {
			continue
		}
		changed = append(changed, fn)
		if patch := f.GetPatch(); patch != "" {
			diffs[fn] = prdiff.ParsePatch(patch)
		}
	}
	return changed, diffs
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
// If changedFiles is non-nil, SAST is limited to those files. Triage is left
// off here; the caller runs it after diff scoping so LLM budget is not burned
// on findings that get dropped.
func runBrolyScan(ctx context.Context, dir string, changedFiles []string) (*core.ScanResult, error) {
	hasAI := os.Getenv("TOGETHER_API_KEY") != ""

	cfg := &core.Config{
		Targets:       []string{dir},
		EnableSecrets: true,
		EnableSCA:     true,
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
			Targets:    sastTargets,
			EnableSAST: true,
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

// filterToPRDiffScope scopes findings to the diff. SCA/Container/License match
// at file level; SAST/Secrets/IaC/Workflow/Dockerfile need the finding's lines
// on an added or modified hunk, falling back to file level when no patch is
// available.
func filterToPRDiffScope(findings []core.Finding, changed []string, diffs map[string]*prdiff.FileDiff) []core.Finding {
	if len(changed) == 0 {
		return nil
	}
	changedSet := make(map[string]bool, len(changed))
	for _, f := range changed {
		changedSet[f] = true
	}

	var filtered []core.Finding
	for _, f := range findings {
		if findingInPRDiffScope(f, changedSet, diffs) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func findingInPRDiffScope(finding core.Finding, changedSet map[string]bool, diffs map[string]*prdiff.FileDiff) bool {
	if !findingMatchesChangedFile(finding, changedSet) {
		return false
	}
	if fileLevelPRFilter(finding.Type) {
		return true
	}
	paths := findingPaths(finding)
	if len(paths) == 0 {
		return true
	}
	sawDiff := false
	for _, path := range paths {
		diff, ok := diffs[path]
		if !ok || diff == nil {
			continue
		}
		sawDiff = true
		if diff.HasLine(finding.StartLine, finding.EndLine) {
			return true
		}
	}
	if !sawDiff {
		return true
	}
	return false
}

func fileLevelPRFilter(t core.ScanType) bool {
	switch t {
	case core.ScanTypeSCA, core.ScanTypeContainer, core.ScanTypeLicense:
		return true
	default:
		return false
	}
}

func findingPaths(finding core.Finding) []string {
	var paths []string
	if path := strings.TrimSpace(finding.FilePath); path != "" {
		if parts := splitCombinedPaths(path); len(parts) > 0 {
			paths = append(paths, parts...)
		} else {
			paths = append(paths, path)
		}
	}
	return paths
}

func findingMatchesChangedFile(finding core.Finding, changedSet map[string]bool) bool {
	if path := strings.TrimSpace(finding.FilePath); path != "" && changedSet[path] {
		return true
	}
	for _, part := range splitCombinedPaths(finding.FilePath) {
		if changedSet[part] {
			return true
		}
	}
	return false
}

func splitCombinedPaths(value string) []string {
	if !strings.Contains(value, ", ") {
		return nil
	}
	var out []string
	for _, part := range strings.Split(value, ", ") {
		path := strings.TrimSpace(part)
		if path != "" {
			out = append(out, path)
		}
	}
	return out
}

type imageRef struct {
	image      string
	dockerfile string
}

// changedDockerfileImages returns the FROM images in changed container specs,
// skipping any image that is unchanged from the base branch.
func changedDockerfileImages(dir string, changed []string, baseImages map[string][]string) []imageRef {
	seen := make(map[string]bool)
	var out []imageRef
	for _, rel := range changed {
		if !container.IsContainerSpecPath(rel) {
			continue
		}
		content, ok := container.ReadDockerfile(dir, rel)
		if !ok {
			continue
		}
		baseSet := make(map[string]bool, len(baseImages[rel]))
		for _, img := range baseImages[rel] {
			baseSet[img] = true
		}
		for _, img := range container.ImagesFromFile(rel, content) {
			seenKey := rel + "\x00" + img
			if seen[seenKey] {
				continue
			}
			if baseSet[img] {
				slog.Info("skipping base image advisory: FROM image unchanged in PR", "image", img, "dockerfile", rel)
				continue
			}
			seen[seenKey] = true
			out = append(out, imageRef{image: img, dockerfile: rel})
		}
	}
	return out
}

func baseImageAdvisoryFinding(ic imageRef) core.Finding {
	f := core.Finding{
		Type:           core.ScanTypeContainer,
		RuleID:         baseImageAdvisoryRuleID,
		RuleName:       fmt.Sprintf("Base image %s may contain OS vulnerabilities", ic.image),
		Severity:       core.SeverityMedium,
		Title:          fmt.Sprintf("Base image %s may contain OS-level vulnerabilities", ic.image),
		Description:    "Base image OS packages may contain vulnerabilities that are not part of the application lockfile.",
		FilePath:       ic.dockerfile,
		PackageName:    ic.image,
		PackageVersion: "base",
		Ecosystem:      "oci",
		BaseImage:      ic.image,
		FixSuggestion:  fmt.Sprintf("Consider using a minimal base image (e.g. %s-slim, %s-alpine, or a distroless image) to reduce the attack surface. Language package vulnerabilities are already covered by SCA.", ic.image, ic.image),
	}
	f.ComputeIdentityKeys()
	return f
}

// baseBranchDockerfileImages fetches the base-branch version of each changed
// container spec so unchanged FROM images don't produce advisories. A fetch
// failure treats that file's FROMs as changed rather than silently skipping.
func baseBranchDockerfileImages(ctx context.Context, client *github.Client, req scanRequest, changed []string) map[string][]string {
	if req.baseBranch == "" || req.prNumber == 0 {
		return nil
	}

	images := make(map[string][]string)
	for _, path := range changed {
		if !container.IsContainerSpecPath(path) {
			continue
		}
		content, err := githubFileContent(ctx, client, req.owner, req.repo, req.baseBranch, path)
		if err != nil {
			slog.Warn("failed to fetch base branch container spec, treating FROM as changed", "path", path, "branch", req.baseBranch, "err", err)
			continue
		}
		images[path] = container.ImagesFromFile(path, content)
	}
	return images
}

func githubFileContent(ctx context.Context, client *github.Client, owner, repo, branch, path string) (string, error) {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch})
	if err != nil {
		return "", err
	}
	if fileContent == nil {
		return "", fmt.Errorf("file not found: %s@%s", path, branch)
	}
	return fileContent.GetContent()
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
