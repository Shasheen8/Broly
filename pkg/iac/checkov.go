package iac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

const defaultFrameworks = "terraform,kubernetes,helm,cloudformation"

type checkovReport struct {
	Results checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovRecord `json:"failed_checks"`
}

type checkovRecord struct {
	CheckID       string  `json:"check_id"`
	CheckName     string  `json:"check_name"`
	CodeBlock     [][]any `json:"code_block"`
	FilePath      string  `json:"file_path"`
	FileLineRange []int   `json:"file_line_range"`
	Resource      string  `json:"resource"`
	Severity      string  `json:"severity"`
	Guideline     string  `json:"guideline"`
}

func runCheckov(ctx context.Context, target string, frameworks string) ([]core.Finding, error) {
	target, err := validateScanTarget(target)
	if err != nil {
		return nil, err
	}
	if frameworks == "" {
		frameworks = defaultFrameworks
	}

	cmd := exec.CommandContext(ctx,
		CheckovExecutable(),
		"-d", target,
		"--output", "json",
		"--quiet",
		"--framework", frameworks,
		"--soft-fail",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if stderr.Len() > 0 {
			slog.Warn("checkov crashed", "target", target, "stderr", tailString(stderr.Bytes(), 1000))
		}
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("checkov not found at %q: install with 'pip install checkov'", CheckovExecutable())
		}
		return nil, fmt.Errorf("run checkov: %w", err)
	}

	findings, parseErr := parseCheckovJSON(out)
	if parseErr != nil {
		slog.Warn("checkov output not valid JSON", "target", target, "stderr", tailString(stderr.Bytes(), 500), "err", parseErr)
		return nil, parseErr
	}
	if err != nil && len(findings) == 0 {
		return nil, fmt.Errorf("run checkov: %w", err)
	}
	// Checkov file_path values are relative to the -d target (often with a
	// leading slash). Join them back onto the scan root so PathStripPrefix
	// can recover repo-relative paths for filterToChangedFiles.
	for i := range findings {
		findings[i].FilePath = resolveCheckovFilePath(target, findings[i].FilePath)
		findings[i].ComputeIdentityKeys()
	}
	return findings, nil
}

func resolveCheckovFilePath(target, filePath string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return filePath
	}
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	return filepath.Join(target, filePath)
}

func validateScanTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty IaC scan target")
	}
	if target[0] == '-' {
		return "", fmt.Errorf("invalid IaC scan target")
	}
	return filepath.Clean(target), nil
}

func parseCheckovJSON(data []byte) ([]core.Finding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var reports []checkovReport
	if err := json.Unmarshal(data, &reports); err != nil {
		var single checkovReport
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, fmt.Errorf("decode checkov json: %w", err2)
		}
		reports = []checkovReport{single}
	}

	out := make([]core.Finding, 0)
	for _, report := range reports {
		for _, rec := range report.Results.FailedChecks {
			if f, ok := checkovRecordToCore(rec); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func checkovRecordToCore(rec checkovRecord) (core.Finding, bool) {
	checkID := strings.TrimSpace(rec.CheckID)
	if checkID == "" {
		return core.Finding{}, false
	}

	filePath := normalizeCheckovPath(rec.FilePath)
	if filePath == "" {
		return core.Finding{}, false
	}

	ruleID := "broly.iac." + checkID
	title := strings.TrimSpace(rec.CheckName)
	if title == "" {
		title = checkID
	}

	startLine := 1
	endLine := startLine
	if len(rec.FileLineRange) >= 2 {
		startLine = rec.FileLineRange[0]
		endLine = rec.FileLineRange[1]
	}
	if startLine < 1 {
		startLine = 1
	}
	if endLine < startLine {
		endLine = startLine
	}

	sev := resolveCheckovSeverity(checkID, rec.Severity, title)

	resource := strings.TrimSpace(rec.Resource)
	snippet := renderCodeBlock(rec.CodeBlock)
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	guideline := strings.TrimSpace(rec.Guideline)
	tags := []string{"iac", "checkov", frameworkTag(checkID)}
	if resource != "" {
		tags = append(tags, "resource:"+resource)
	}

	f := core.Finding{
		Type:          core.ScanTypeIaC,
		RuleID:        ruleID,
		RuleName:      title,
		Severity:      sev,
		Title:         title,
		Description:   title,
		FilePath:      filePath,
		StartLine:     startLine,
		EndLine:       endLine,
		Snippet:       snippet,
		ArtifactPath:  resource,
		Tags:          tags,
		Timestamp:     time.Now(),
		FixSuggestion: remediation(checkID, guideline),
	}
	if guideline != "" {
		f.References = []string{guideline}
	}
	f.ComputeIdentityKeys()
	return f, true
}

func normalizeCheckovPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." {
		return ""
	}
	if filepath.IsAbs(p) {
		p = strings.TrimPrefix(p, "/")
	}
	return p
}

func renderCodeBlock(block [][]any) string {
	if len(block) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, entry := range block {
		if len(entry) < 2 {
			continue
		}
		lineNum := 0
		switch v := entry[0].(type) {
		case float64:
			lineNum = int(v)
		case int:
			lineNum = v
		}
		lineText := ""
		if s, ok := entry[1].(string); ok {
			lineText = s
		}
		fmt.Fprintf(&sb, "%4d  %s\n", lineNum, lineText)
	}
	return sb.String()
}

func frameworkTag(checkID string) string {
	id := strings.ToUpper(checkID)
	switch {
	case strings.HasPrefix(id, "CKV_AWS_"):
		return "aws"
	case strings.HasPrefix(id, "CKV_K8S_"):
		return "kubernetes"
	case strings.HasPrefix(id, "CKV_AZURE_"):
		return "azure"
	case strings.HasPrefix(id, "CKV_GCP_"):
		return "gcp"
	default:
		return "generic"
	}
}

func tailString(data []byte, max int) string {
	s := string(data)
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max:]
}
