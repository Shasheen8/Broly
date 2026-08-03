package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
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
		Name:        "Broly Security Scan",
		HeadSHA:     req.headSHA,
		Status:      github.Ptr("completed"),
		Conclusion:  github.Ptr(conclusion),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output:      output,
	})
	if err != nil {
		slog.Error("create check run", "err", err)
	}
}

func postCheckRunError(ctx context.Context, client *github.Client, req scanRequest, msg string) {
	_, _, err := client.Checks.CreateCheckRun(ctx, req.owner, req.repo, github.CreateCheckRunOptions{
		Name:        "Broly Security Scan",
		HeadSHA:     req.headSHA,
		Status:      github.Ptr("completed"),
		Conclusion:  github.Ptr("neutral"),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr("Broly: scan error"),
			Summary: github.Ptr(fmt.Sprintf("⚠️ %s", msg)),
		},
	})
	if err != nil {
		slog.Error("create error check run", "err", err)
	}
}

func postPRComment(ctx context.Context, client *github.Client, req scanRequest, result *core.ScanResult) {
	if req.prNumber == 0 {
		return
	}

	body := buildCommentBody(result)

	// Look for existing Broly comment to update in-place (paginate).
	var existingID int64
	var err error
	opts := &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		var comments []*github.IssueComment
		var resp *github.Response
		comments, resp, err = client.Issues.ListComments(ctx, req.owner, req.repo, req.prNumber, opts)
		if err != nil {
			slog.Error("list comments", "err", err)
			break
		}
		for _, c := range comments {
			if strings.Contains(c.GetBody(), "<!-- broly-scan -->") {
				existingID = c.GetID()
				break
			}
		}
		if existingID != 0 || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
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

func buildAnnotations(result *core.ScanResult, limit int) []*github.CheckRunAnnotation {
	var annotations []*github.CheckRunAnnotation
	for _, f := range result.Findings {
		if len(annotations) >= limit {
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
			EndLine:         github.Ptr(max(f.EndLine, f.StartLine)),
			AnnotationLevel: github.Ptr(level),
			Message:         github.Ptr(msg),
			Title:           github.Ptr(fmt.Sprintf("[%s] %s", f.Severity, f.RuleName)),
		})
	}
	return annotations
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

	// Sort findings: critical first, then high, medium, low; SAST before SCA.
	sorted := make([]core.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		return sorted[i].Type < sorted[j].Type
	})

	limit := 30
	for i, f := range sorted {
		if i >= limit {
			break
		}
		icon := sevIcon[f.Severity.String()]
		issue := f.RuleName
		if len(issue) > 55 {
			issue = issue[:52] + "..."
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
			advSuffix := ""
			if f.Severity == core.SeverityCritical && f.AdversarialVerdict == "CONFIRMED" {
				advSuffix = " · ⚔️ Adversarial confirmed"
			}
			fmt.Fprintf(&b, "| %s&nbsp;%s | %s | %s | %s | %s&nbsp;%s%s%s |\n",
				icon, f.Severity, f.Type.Label(), issue, loc, vIcon, f.Verdict, conf, advSuffix)
		} else {
			fmt.Fprintf(&b, "| %s&nbsp;%s | %s | %s | %s |\n",
				icon, f.Severity, f.Type.Label(), issue, loc)
		}
	}

	// Fix suggestions for true positives.
	var fixes []core.Finding
	for _, f := range result.Findings {
		if (f.FixSuggestion != "" || f.FixCode != "") && f.Verdict == "TRUE_POSITIVE" {
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
			fmt.Fprintf(&b, "<details><summary>🔧 %s</summary>\n\n", title)
			if f.FixSuggestion != "" {
				fmt.Fprintf(&b, "%s\n\n", f.FixSuggestion)
			}
			if f.FixCode != "" {
				fmt.Fprintf(&b, "```\n%s\n```\n", f.FixCode)
			}
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
				rule = rule[:47] + "..."
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

	// Exploit chains section.
	if len(result.ExploitChains) > 0 {
		b.WriteString("\n### ⛓️ Exploit Chains\n\n")
		for _, c := range result.ExploitChains {
			fmt.Fprintf(&b, "<details><summary>%s (%s)</summary>\n\n", c.Title, c.Severity)
			for _, step := range c.Steps {
				fmt.Fprintf(&b, "%s\n", step)
			}
			if c.Narrative != "" {
				fmt.Fprintf(&b, "\n> %s\n", c.Narrative)
			}
			b.WriteString("\n</details>\n")
		}
	}

	// Supply chain threats section.
	var supplyChainFindings []core.Finding
	for _, f := range result.Findings {
		if f.IsMaliciousPackage() {
			supplyChainFindings = append(supplyChainFindings, f)
		}
	}
	if len(supplyChainFindings) > 0 {
		b.WriteString("\n### 🦠 Supply Chain Threats\n\n")
		for _, f := range supplyChainFindings {
			loc := ""
			if f.FilePath != "" {
				loc = f.FilePath
				if f.StartLine > 0 {
					loc += fmt.Sprintf(":%d", f.StartLine)
				}
			}
			desc := f.Description
			if desc == "" {
				desc = f.Title
			}
			fmt.Fprintf(&b, "- 🔴 **%s** (%s) in %s: %s\n", f.PackageName, f.RuleID, loc, desc)
			for _, ref := range f.References {
				fmt.Fprintf(&b, "  - [%s](%s)\n", ref, ref)
			}
		}
		b.WriteString("\n> These are not CVEs — they are known-malicious packages. Remove them immediately.\n")
	}

	// Dismissed false positives (adversarial + high-confidence triage).
	var dismissed []core.Finding
	for _, f := range result.Findings {
		if f.AdversarialVerdict == "DISPUTED" || f.AdversarialVerdict == "FALSIFIED" {
			dismissed = append(dismissed, f)
		} else if f.Verdict == "FALSE_POSITIVE" && f.Confidence == "HIGH" {
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) > 0 {
		b.WriteString("\n### 🟢 Dismissed False Positives\n\n")
		for _, f := range dismissed {
			reason := f.AdversarialReason
			if reason == "" {
				reason = f.VerdictReason
			}
			if reason == "" {
				reason = "Marked as false positive."
			}
			source := "triage"
			if f.AdversarialVerdict == "DISPUTED" || f.AdversarialVerdict == "FALSIFIED" {
				source = strings.ToLower(f.AdversarialVerdict)
			}
			fmt.Fprintf(&b, "- **%s** · %s: %s\n", f.RuleName, source, reason)
		}
	}

	b.WriteString("\n> [Broly](https://github.com/Shasheen8/Broly) — Secrets · SCA · SAST · Powered by Together AI\n")
	return b.String()
}
