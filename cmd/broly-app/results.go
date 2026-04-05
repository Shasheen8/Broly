package main

import (
	"context"
	"fmt"
	"log/slog"
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
		slog.Error("create check run", "err", err)
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
		slog.Error("list comments", "err", err)
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
		slog.Error("post PR comment", "err", err)
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
			fmt.Fprintf(&b, "%s&nbsp;**%d %s**  ", icon, c, sev)
		}
	}
	b.WriteString("\n\n")

	// Findings table.
	hasTriage := false
	for _, f := range result.Findings {
		if f.Verdict != "" {
			hasTriage = true
			break
		}
	}

	if hasTriage {
		b.WriteString("| Severity | Scanner | Issue | Location | Verdict |\n")
		b.WriteString("|----------|---------|-------|----------|--------|\n")
	} else {
		b.WriteString("| Severity | Scanner | Issue | Location |\n")
		b.WriteString("|----------|---------|-------|----------|\n")
	}

	verdictIcon := map[string]string{
		"TRUE_POSITIVE": "🔺", "FALSE_POSITIVE": "🟢",
	}

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
		if hasTriage {
			vIcon := verdictIcon[f.Verdict]
			if vIcon == "" {
				vIcon = "❔"
			}
			conf := ""
			if f.Confidence != "" {
				conf = " · Confidence: " + f.Confidence
			}
			fmt.Fprintf(&b, "| %s&nbsp;%s | %s | %s | %s | %s&nbsp;%s%s |\n",
				icon, f.Severity, strings.ToUpper(string(f.Type)), issue, loc, vIcon, f.Verdict, conf)
		} else {
			fmt.Fprintf(&b, "| %s&nbsp;%s | %s | %s | %s |\n",
				icon, f.Severity, strings.ToUpper(string(f.Type)), issue, loc)
		}
	}

	// Fix suggestions for true positives.
	var fixes []core.Finding
	for _, f := range result.Findings {
		if f.FixSuggestion != "" && f.Verdict == "TRUE_POSITIVE" {
			fixes = append(fixes, f)
		}
		if len(fixes) >= 10 {
			break
		}
	}
	if len(fixes) > 0 {
		b.WriteString("\n### Fix Suggestions\n\n")
		for _, f := range fixes {
			title := f.RuleName
			if f.FilePath != "" {
				title += " — " + f.FilePath
				if f.StartLine > 0 {
					title += fmt.Sprintf(":%d", f.StartLine)
				}
			}
			fmt.Fprintf(&b, "<details><summary>🔧 %s</summary>\n\n```\n%s\n```\n", title, f.FixSuggestion)
			if f.Explanation != "" {
				fmt.Fprintf(&b, "\n> %s\n", f.Explanation)
			} else if f.VerdictReason != "" {
				fmt.Fprintf(&b, "\n> %s\n", f.VerdictReason)
			}
			b.WriteString("\n</details>\n")
		}
	}

	// False positive checkboxes.
	var fpFindings []core.Finding
	for _, f := range result.Findings {
		if f.Fingerprint != "" {
			fpFindings = append(fpFindings, f)
		}
		if len(fpFindings) >= limit {
			break
		}
	}
	if len(fpFindings) > 0 {
		b.WriteString("\n### Mark as False Positive\n\n")
		for _, f := range fpFindings {
			icon := sevIcon[f.Severity.String()]
			rule := f.RuleName
			if len(rule) > 50 {
				rule = rule[:50]
			}
			loc := ""
			if f.FilePath != "" {
				loc = f.FilePath
				if f.StartLine > 0 {
					loc += fmt.Sprintf(":%d", f.StartLine)
				}
			}
			fmt.Fprintf(&b, "- [ ] %s %s · %s", icon, f.Severity, rule)
			if loc != "" {
				fmt.Fprintf(&b, " · %s", loc)
			}
			fmt.Fprintf(&b, " <!-- fp:%s -->\n", f.Fingerprint)
		}
		b.WriteString("\n*Check a box to suppress a finding. Broly will auto-update `.broly-baseline.yaml` on the next commit.*\n")
	}

	if len(result.Findings) > limit {
		fmt.Fprintf(&b, "\n> Showing top %d of %d findings.\n", limit, len(result.Findings))
	}

	b.WriteString("\n> [Broly](https://github.com/Shasheen8/Broly) — Secrets · SCA · SAST · Powered by Together AI\n")
	return b.String()
}
