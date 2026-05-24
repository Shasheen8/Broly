package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

func TestBuildCommentBodyCleanScan(t *testing.T) {
	body := buildCommentBody(&core.ScanResult{Findings: nil})
	for _, want := range []string{
		"<!-- broly-scan -->",
		"## Broly Security Scan",
		"No findings detected",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestBuildCommentBodyShowsTriageConfidenceAndFixes(t *testing.T) {
	body := buildCommentBody(&core.ScanResult{Findings: []core.Finding{{
		Type:          core.ScanTypeSAST,
		Severity:      core.SeverityCritical,
		Verdict:       "TRUE_POSITIVE",
		Confidence:    "HIGH",
		RuleName:      "sql_concat",
		Title:         "SQL string concatenation",
		FilePath:      "app.py",
		StartLine:     10,
		FixSuggestion: "Use parameterized queries.",
		FixCode:       "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
		Fingerprint:   "fp123",
	}}})
	for _, want := range []string{
		"| Verdict |",
		"TRUE_POSITIVE",
		"Confidence: HIGH",
		"### Fix Suggestions",
		"Use parameterized queries.",
		"cursor.execute",
		"### Mark as False Positive",
		"<!-- fp:fp123 -->",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestBuildCommentBodyWithoutTriageOmitsVerdictColumn(t *testing.T) {
	body := buildCommentBody(&core.ScanResult{Findings: []core.Finding{{
		Type:     core.ScanTypeSCA,
		Severity: core.SeverityHigh,
		RuleName: "GHSA-xxxx",
		FilePath: "go.mod",
	}}})
	if strings.Contains(body, "| Verdict |") {
		t.Fatalf("expected no verdict column:\n%s", body)
	}
	if !strings.Contains(body, "| SCA |") {
		t.Fatalf("expected scanner column:\n%s", body)
	}
}

func TestBuildCommentBodyTruncatesAtLimit(t *testing.T) {
	findings := make([]core.Finding, 35)
	for i := range findings {
		findings[i] = core.Finding{
			Type:     core.ScanTypeSAST,
			Severity: core.SeverityMedium,
			RuleName: "rule",
			FilePath: "f.go",
		}
	}
	body := buildCommentBody(&core.ScanResult{Findings: findings})
	if !strings.Contains(body, "Showing top 30 of 35") {
		t.Fatalf("missing truncation note:\n%s", body)
	}
}

func TestBuildSummaryWithFindings(t *testing.T) {
	summary := buildSummary(&core.ScanResult{
		Findings: []core.Finding{
			{Severity: core.SeverityCritical},
			{Severity: core.SeverityHigh},
		},
		Duration: 2 * time.Second,
	})
	for _, want := range []string{"2 findings", "1 CRITICAL", "1 HIGH", "2s"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("missing %q in %q", want, summary)
		}
	}
}

func TestPreviewPRCommentMarkdown(t *testing.T) {
	if os.Getenv("BROLY_PREVIEW") == "" {
		t.Skip("set BROLY_PREVIEW=1 to print sample GitHub PR comment markdown")
	}
	body := buildCommentBody(&core.ScanResult{Findings: []core.Finding{
		{
			Type: core.ScanTypeSAST, Severity: core.SeverityCritical,
			Verdict: "TRUE_POSITIVE", Confidence: "HIGH",
			RuleName: "sql-injection", FilePath: "api/handlers.py", StartLine: 42,
			FixSuggestion: "Use parameterized queries.", FixCode: "cursor.execute(...)",
			Fingerprint: "abc123",
		},
		{
			Type: core.ScanTypeSCA, Severity: core.SeverityHigh,
			RuleName: "GHSA-xxxx-yyyy", FilePath: "requirements.txt",
			PackageName: "requests", PackageVersion: "2.25.0",
		},
	}})
	t.Log("\n" + body)
}

func TestBuildAnnotationsRespectsLimit(t *testing.T) {
	findings := make([]core.Finding, 60)
	for i := range findings {
		findings[i] = core.Finding{
			Type:      core.ScanTypeSAST,
			Severity:  core.SeverityHigh,
			RuleName:  "x",
			Title:     "issue",
			FilePath:  "a.go",
			StartLine: 1,
		}
	}
	ann := buildAnnotations(&core.ScanResult{Findings: findings}, 50)
	if len(ann) != 50 {
		t.Fatalf("annotations = %d, want 50", len(ann))
	}
}
