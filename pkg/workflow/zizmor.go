package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

type zizmorFinding struct {
	Ident          string `json:"ident"`
	Desc           string `json:"desc"`
	URL            string `json:"url"`
	Determinations struct {
		Confidence string `json:"confidence"`
		Severity   string `json:"severity"`
	} `json:"determinations"`
	Locations []zizmorLocation `json:"locations"`
	Ignored   bool             `json:"ignored"`
}

type zizmorLocation struct {
	Symbolic struct {
		Key struct {
			Local *struct {
				GivenPath string `json:"given_path"`
			} `json:"Local"`
			Remote *struct {
				Path string `json:"path"`
			} `json:"Remote"`
		} `json:"key"`
		Annotation string `json:"annotation"`
		Kind       string `json:"kind"`
	} `json:"symbolic"`
	Concrete struct {
		Location struct {
			StartPoint struct{ Row, Column int } `json:"start_point"`
			EndPoint   struct{ Row, Column int } `json:"end_point"`
		} `json:"location"`
		Feature string `json:"feature"`
	} `json:"concrete"`
}

func runZizmor(ctx context.Context, target string) ([]core.Finding, error) {
	target, err := validateScanTarget(target)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, ZizmorExecutable(), "--offline", "--format=json-v1", "--no-exit-codes", target)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("zizmor not found at %q: install with 'pip install zizmor'", ZizmorExecutable())
		}
		return nil, fmt.Errorf("run zizmor: %w", err)
	}
	findings, parseErr := parseZizmorJSON(out)
	if parseErr != nil {
		return nil, parseErr
	}
	if err != nil && len(findings) == 0 {
		return nil, fmt.Errorf("run zizmor: %w", err)
	}
	return findings, nil
}

func validateScanTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty workflow scan target")
	}
	if target[0] == '-' {
		return "", fmt.Errorf("invalid workflow scan target")
	}
	return filepath.Clean(target), nil
}

func parseZizmorJSON(data []byte) ([]core.Finding, error) {
	var raw []zizmorFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode zizmor json-v1: %w", err)
	}
	out := make([]core.Finding, 0, len(raw))
	for i := range raw {
		if raw[i].Ignored {
			continue
		}
		if f, ok := zizmorFindingToCore(raw[i]); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func zizmorFindingToCore(zf zizmorFinding) (core.Finding, bool) {
	loc, ok := primaryZizmorLocation(zf.Locations)
	if !ok {
		return core.Finding{}, false
	}
	filePath := workflowFilePath(loc)
	if filePath == "" {
		return core.Finding{}, false
	}
	ident := strings.TrimSpace(zf.Ident)
	if ident == "" {
		return core.Finding{}, false
	}
	ruleID := "zizmor." + ident

	startLine := loc.Concrete.Location.StartPoint.Row + 1
	if startLine < 1 {
		startLine = 1
	}
	endLine := loc.Concrete.Location.EndPoint.Row + 1
	if endLine < startLine {
		endLine = startLine
	}

	sev := core.ParseSeverity(zf.Determinations.Severity)
	if sev == core.SeverityInfo && zf.Determinations.Severity == "" {
		sev = core.SeverityMedium
	}

	title := strings.TrimSpace(zf.Desc)
	if title == "" {
		title = ruleID
	}
	desc := strings.TrimSpace(loc.Symbolic.Annotation)
	if desc == "" {
		desc = title
	}

	snippet := loc.Concrete.Feature
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	tags := []string{"workflow", "github-actions", "zizmor"}
	if conf := strings.TrimSpace(zf.Determinations.Confidence); conf != "" {
		tags = append(tags, "confidence:"+strings.ToLower(conf))
	}

	docURL := strings.TrimSpace(zf.URL)
	f := core.Finding{
		Type:          core.ScanTypeWorkflow,
		RuleID:        ruleID,
		RuleName:      title,
		Severity:      sev,
		Title:         title,
		Description:   desc,
		FilePath:      filePath,
		StartLine:     startLine,
		EndLine:       endLine,
		StartColumn:   loc.Concrete.Location.StartPoint.Column + 1,
		EndColumn:     loc.Concrete.Location.EndPoint.Column + 1,
		Snippet:       snippet,
		Tags:          tags,
		Timestamp:     time.Now(),
		FixSuggestion: remediation(ident, docURL),
	}
	if docURL != "" {
		f.References = []string{docURL}
	}
	f.ComputeIdentityKeys()
	return f, true
}

func primaryZizmorLocation(locs []zizmorLocation) (zizmorLocation, bool) {
	if len(locs) == 0 {
		return zizmorLocation{}, false
	}
	for _, loc := range locs {
		if strings.EqualFold(loc.Symbolic.Kind, "Primary") {
			return loc, true
		}
	}
	for _, loc := range locs {
		if !strings.EqualFold(loc.Symbolic.Kind, "Hidden") {
			return loc, true
		}
	}
	return locs[0], true
}

func workflowFilePath(loc zizmorLocation) string {
	if loc.Symbolic.Key.Local != nil {
		return normalizeWorkflowPath(loc.Symbolic.Key.Local.GivenPath)
	}
	if loc.Symbolic.Key.Remote != nil {
		return normalizeWorkflowPath(loc.Symbolic.Key.Remote.Path)
	}
	return ""
}

func normalizeWorkflowPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	if strings.HasPrefix(p, "../") || strings.Contains(p, "/../") {
		return ""
	}
	return p
}
