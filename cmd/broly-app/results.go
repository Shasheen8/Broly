package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/go-github/v69/github"

	"github.com/Shasheen8/Broly/pkg/core"
)

func postCheckRun(ctx context.Context, client *github.Client, req scanRequest, result *core.ScanResult) {
	conclusion := "success"
	if len(result.Findings) > 0 {
		conclusion = "failure"
	}

	title := fmt.Sprintf("Broly: %d findings", len(result.Findings))
	if len(result.Findings) == 0 {
		title = "Broly: clean scan"
	}

	summary := buildSummary(result)

	annotations := buildAnnotations(result, 50)

	output := &github.CheckRunOutput{
		Title:       github.Ptr(title),
		Summary:     github.Ptr(summary),
		Annotations: annotations,
	}

	_, _, err := client.Checks.CreateCheckRun(ctx, req.owner, req.repo, github.CreateCheckRunOptions{
		Name:       "Broly Security Scan",
		HeadSHA:    req.headSHA,
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr(conclusion),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output:     output,
	})
	if err != nil {
		log.Printf("create check run: %v", err)
	}
}

func postPRComment(ctx context.Context, client *github.Client, req scanRequest, result *core.ScanResult) {
	if req.prNumber == 0 {
		return
	}

	body := buildCommentBody(result)

	// Look for existing Broly comment to update in-place.
	comments, _, err := client.Issues.ListComments(ctx, req.owner, req.repo, req.prNumber, &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: 50},
	})
	if err != nil {
		log.Printf("list comments: %v", err)
	}

	var existingID int64
	for _, c := range comments {
		if strings.Contains(c.GetBody(), "<!-- broly-scan -->") {
			existingID = c.GetID()
			break
		}
	}

	if existingID != 0 {
		_, _, err = client.Issues.EditComment(ctx, req.owner, req.repo, existingID, &github.IssueComment{
			Body: github.Ptr(body),
		})
	} else {
		_, _, err = client.Issues.CreateComment(ctx, req.owner, req.repo, req.prNumber, &github.IssueComment{
			Body: github.Ptr(body),
		})
	}
	if err != nil {
		log.Printf("post PR comment: %v", err)
	}
}

func buildSummary(result *core.ScanResult) string {
	if len(result.Findings) == 0 {
		return "No security findings detected."
	}

	counts := make(map[core.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	var parts []string
	for _, sev := range []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	return fmt.Sprintf("%d findings: %s (scanned in %s)",
		len(result.Findings), strings.Join(parts, ", "), result.Duration.Round(time.Millisecond))
}

func buildAnnotations(result *core.ScanResult, max int) []*github.CheckRunAnnotation {
	var annotations []*github.CheckRunAnnotation
	for _, f := range result.Findings {
		if len(annotations) >= max {
			break
		}
		if f.FilePath == "" || f.StartLine < 1 {
			continue
		}

		level := "warning"
		if f.Severity >= core.SeverityHigh {
			level = "failure"
		} else if f.Severity <= core.SeverityLow {
			level = "notice"
		}

		msg := f.Title
		if f.Description != "" && f.Description != f.Title {
			msg += ": " + f.Description
		}

		annotations = append(annotations, &github.CheckRunAnnotation{
			Path:            github.Ptr(f.FilePath),
			StartLine:       github.Ptr(f.StartLine),
			EndLine:         github.Ptr(max1(f.EndLine, f.StartLine)),
			AnnotationLevel: github.Ptr(level),
			Message:         github.Ptr(msg),
			Title:           github.Ptr(fmt.Sprintf("[%s] %s", f.Severity, f.RuleName)),
		})
	}
	return annotations
}

func max1(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildCommentBody(result *core.ScanResult) string {
	var b strings.Builder
	b.WriteString("<!-- broly-scan -->\n")
	b.WriteString("## Broly Security Scan\n\n")

	if len(result.Findings) == 0 {
		b.WriteString("✅ No findings detected.\n")
		b.WriteString("\n> [Broly](https://github.com/Shasheen8/Broly)\n")
		return b.String()
	}

	sevIcon := map[string]string{
		"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵",
	}

	// Summary counts.
	counts := make(map[core.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	for _, sev := range []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow} {
		if c := counts[sev]; c > 0 {
			icon := sevIcon[sev.String()]
			fmt.Fprintf(&b, "%s **%d %s**  ", icon, c, sev)
		}
	}
	b.WriteString("\n\n")

	// Findings table.
	b.WriteString("| Severity | Scanner | Issue | Location |\n")
	b.WriteString("|----------|---------|-------|----------|\n")

	limit := 30
	for i, f := range result.Findings {
		if i >= limit {
			break
		}
		icon := sevIcon[f.Severity.String()]
		issue := f.RuleName
		if len(issue) > 55 {
			issue = issue[:55]
		}
		loc := ""
		if f.FilePath != "" {
			loc = fmt.Sprintf("`%s", f.FilePath)
			if f.StartLine > 0 {
				loc += fmt.Sprintf(":%d", f.StartLine)
			}
			loc += "`"
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s | %s |\n",
			icon, f.Severity, strings.ToUpper(string(f.Type)), issue, loc)
	}

	if len(result.Findings) > limit {
		fmt.Fprintf(&b, "\n> Showing top %d of %d findings.\n", limit, len(result.Findings))
	}

	b.WriteString("\n> [Broly](https://github.com/Shasheen8/Broly)\n")
	return b.String()
}
