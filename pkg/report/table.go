package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Shasheen8/Broly/pkg/core"
)

// ANSI color codes — disabled when output is not a TTY.
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	yellow    = "\033[33m"
	cyan      = "\033[36m"
	white     = "\033[97m"
	brightRed = "\033[91m"
	orange    = "\033[38;5;214m"
	blue      = "\033[34m"
	gray      = "\033[90m"
	green     = "\033[32m"
	magenta   = "\033[35m"
	bgRed     = "\033[41m"
)

func isColorEnabled(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			return true
		}
	}
	return false
}

type color struct {
	enabled bool
}

type tableColumn struct {
	width int
	value string
	style func(string) string
}

func (c color) s(code, text string) string {
	if !c.enabled {
		return text
	}
	return code + text + reset
}

type TableFormatter struct{}

func (f *TableFormatter) Name() string { return "table" }

func (f *TableFormatter) Format(w io.Writer, result *core.ScanResult) error {
	clr := color{enabled: isColorEnabled(w)}

	if len(result.Findings) == 0 && len(result.MissingRequired) == 0 {
		fmt.Fprintf(w, "\n  %s\n\n", clr.s(green+bold, "✔  No findings detected. Clean scan!"))
		return nil
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity != result.Findings[j].Severity {
			return result.Findings[i].Severity > result.Findings[j].Severity
		}
		return result.Findings[i].FilePath < result.Findings[j].FilePath
	})

	byScanType := make(map[core.ScanType][]core.Finding)
	for _, finding := range result.Findings {
		byScanType[finding.Type] = append(byScanType[finding.Type], finding)
	}

	printBanner(w, clr)

	for _, scanType := range []core.ScanType{core.ScanTypeSecrets, core.ScanTypeSCA, core.ScanTypeSAST, core.ScanTypeDockerfile, core.ScanTypeContainer, core.ScanTypeLicense} {
		findings, ok := byScanType[scanType]
		if !ok {
			continue
		}
		label := scanTypeLabel(scanType)
		fmt.Fprintf(w, "\n  %s %s\n\n",
			clr.s(cyan+bold, fmt.Sprintf("▸ %s", label)),
			clr.s(gray, fmt.Sprintf("(%d finding%s)", len(findings), plural(len(findings)))),
		)
		if scanType == core.ScanTypeSAST {
			printSASTTable(w, clr, findings)
			continue
		}
		printScanTypeTable(w, clr, scanType, findings)
	}

	printSummary(w, clr, result)
	return nil
}

func scanTypeLabel(t core.ScanType) string {
	switch t {
	case core.ScanTypeSecrets:
		return "SECRETS"
	case core.ScanTypeSCA:
		return "SCA"
	case core.ScanTypeSAST:
		return "SAST"
	case core.ScanTypeDockerfile:
		return "DOCKERFILE"
	case core.ScanTypeContainer:
		return "CONTAINER"
	case core.ScanTypeLicense:
		return "LICENSE"
	default:
		return strings.ToUpper(string(t))
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// runeWidth returns the terminal column width of a rune (1 or 2).
func runeWidth(r rune) int {
	switch {
	case r == 0x26A1: // ⚡ LIGHTNING — wide in most terminals
		return 2
	case r >= 0x1F300 && r <= 0x1FAFF: // general emoji block
		return 2
	case r >= 0x4E00 && r <= 0x9FFF: // CJK unified ideographs
		return 2
	default:
		return 1
	}
}

// visibleLen returns the printable column width of s, ignoring ANSI escape sequences
// and counting wide characters (emoji, CJK) as 2 columns.
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// Skip ANSI escape sequence up to and including 'm'.
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		n += runeWidth(r)
		i += size
	}
	return n
}

// bannerCentered prints a banner row with content centered within the box.
func bannerCentered(w io.Writer, clr color, content string) {
	const width = 54
	vl := visibleLen(content)
	leftPad := (width - vl) / 2
	rightPad := width - vl - leftPad
	if leftPad < 0 {
		leftPad = 0
	}
	if rightPad < 0 {
		rightPad = 0
	}
	fmt.Fprintf(w, "  %s%s%s%s%s\n",
		clr.s(cyan, "║"),
		strings.Repeat(" ", leftPad),
		content,
		strings.Repeat(" ", rightPad),
		clr.s(cyan, "║"),
	)
}

func printBanner(w io.Writer, clr color) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", clr.s(cyan, "╔══════════════════════════════════════════════════════╗"))
	bannerCentered(w, clr, "")
	bannerCentered(w, clr,
		"⚡  "+clr.s(bold+brightRed, "BROLY")+"  "+clr.s(bold+white, "Berserker Vulnerability Scanner"),
	)
	bannerCentered(w, clr,
		clr.s(dim+cyan, "Secrets · SCA · SAST · Powered by Together AI"),
	)
	bannerCentered(w, clr, "")
	fmt.Fprintf(w, "  %s\n", clr.s(cyan, "╚══════════════════════════════════════════════════════╝"))
	fmt.Fprintln(w)
}

func severityColor(sev core.Severity, clr color) string {
	switch sev {
	case core.SeverityCritical:
		return clr.s(bold+brightRed, sev.String())
	case core.SeverityHigh:
		return clr.s(bold+orange, sev.String())
	case core.SeverityMedium:
		return clr.s(bold+yellow, sev.String())
	case core.SeverityLow:
		return clr.s(bold+blue, sev.String())
	default:
		return clr.s(gray, sev.String())
	}
}

func printScanTypeTable(w io.Writer, clr color, scanType core.ScanType, findings []core.Finding) {
	switch scanType {
	case core.ScanTypeSecrets:
		printSecretsTable(w, clr, findings)
	case core.ScanTypeSCA:
		printSCATable(w, clr, findings)
	case core.ScanTypeContainer:
		printContainerTable(w, clr, findings)
	case core.ScanTypeSAST:
		printSASTTable(w, clr, findings)
	case core.ScanTypeDockerfile:
		printSASTTable(w, clr, findings)
	case core.ScanTypeLicense:
		printSASTTable(w, clr, findings)
	}
}

func printSecretsTable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-10s  %-28s  %-40s  %s", "SEVERITY", "RULE", "FILE", "REDACTED"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 116)))
	for i, f := range findings {
		mainLines := printTableRow(w, []tableColumn{
			{width: 10, value: f.Severity.String(), style: func(s string) string { return severityColor(f.Severity, clr) }},
			{width: 28, value: f.RuleName, style: func(s string) string { return s }},
			{width: 40, value: formatLocation(f), style: func(s string) string { return clr.s(dim, s) }},
			{width: 24, value: f.Redacted, style: func(s string) string { return clr.s(gray, s) }},
		})
		detailLines := printFindingDetails(w, clr, f)
		if i < len(findings)-1 && (mainLines > 1 || detailLines > 0) {
			fmt.Fprintln(w)
		}
	}
}

func printSCATable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-10s  %-20s  %-20s  %-12s  %-12s  %s", "SEVERITY", "VULN ID", "PACKAGE", "VERSION", "FIXED", "ECOSYSTEM"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 116)))
	for i, f := range findings {
		fixedValue := f.FixedVersion
		fixedStyle := func(s string) string { return clr.s(green, s) }
		if fixedValue == "" {
			fixedValue = "no patch"
			fixedStyle = func(s string) string { return clr.s(red, s) }
		}
		mainLines := printTableRow(w, []tableColumn{
			{width: 10, value: f.Severity.String(), style: func(s string) string { return severityColor(f.Severity, clr) }},
			{width: 20, value: f.RuleID, style: func(s string) string { return clr.s(cyan, s) }},
			{width: 20, value: f.PackageName, style: func(s string) string { return clr.s(white, s) }},
			{width: 12, value: f.PackageVersion, style: func(s string) string { return clr.s(gray, s) }},
			{width: 12, value: fixedValue, style: fixedStyle},
			{width: 14, value: f.Ecosystem, style: func(s string) string { return clr.s(dim, s) }},
		})
		detailLines := printFindingDetails(w, clr, f)
		if i < len(findings)-1 && (mainLines > 1 || detailLines > 0) {
			fmt.Fprintln(w)
		}
	}
}

func printContainerTable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-10s  %-20s  %-20s  %-12s  %-12s  %-14s  %s", "SEVERITY", "VULN ID", "PACKAGE", "VERSION", "FIXED", "ECOSYSTEM", "LAYER"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 130)))
	for i, f := range findings {
		fixedValue := f.FixedVersion
		fixedStyle := func(s string) string { return clr.s(green, s) }
		if fixedValue == "" {
			fixedValue = "no patch"
			fixedStyle = func(s string) string { return clr.s(red, s) }
		}
		layerValue := "n/a"
		layerStyle := func(s string) string { return clr.s(gray, s) }
		if f.LayerIndex > 0 {
			layerValue = fmt.Sprintf("#%d", f.LayerIndex)
			layerStyle = func(s string) string { return clr.s(yellow, s) }
		}
		mainLines := printTableRow(w, []tableColumn{
			{width: 10, value: f.Severity.String(), style: func(s string) string { return severityColor(f.Severity, clr) }},
			{width: 20, value: f.RuleID, style: func(s string) string { return clr.s(cyan, s) }},
			{width: 20, value: f.PackageName, style: func(s string) string { return clr.s(white, s) }},
			{width: 12, value: f.PackageVersion, style: func(s string) string { return clr.s(gray, s) }},
			{width: 12, value: fixedValue, style: fixedStyle},
			{width: 14, value: f.Ecosystem, style: func(s string) string { return clr.s(dim, s) }},
			{width: 10, value: layerValue, style: layerStyle},
		})
		detailLines := printFindingDetails(w, clr, f)
		if i < len(findings)-1 && (mainLines > 1 || detailLines > 0) {
			fmt.Fprintln(w)
		}
	}
}

func printSASTTable(w io.Writer, clr color, findings []core.Finding) {
	const (
		severityWidth   = 12
		detailsWidth    = 46
		assessmentWidth = 34
		fixWidth        = 42
	)

	printBoundedTableRow(w, []tableColumn{
		{width: severityWidth, value: clr.s(bold+white, "SEVERITY")},
		{width: detailsWidth, value: clr.s(bold+white, "FINDING DETAILS")},
		{width: assessmentWidth, value: clr.s(bold+white, "ASSESSMENT / CONTEXT")},
		{width: fixWidth, value: clr.s(bold+white, "TARGETED FIX")},
	})
	printBoundedDivider(w, severityWidth, detailsWidth, assessmentWidth, fixWidth)
	for _, f := range findings {
		printBoundedTableRow(w, []tableColumn{
			{width: severityWidth, value: severityLabel(f.Severity), style: func(s string) string { return styleSeverityLabel(f.Severity, clr, s) }},
			{width: detailsWidth, value: sastFindingDetailsCell(f)},
			{width: assessmentWidth, value: sastAssessmentContextCell(f)},
			{width: fixWidth, value: sastTargetedFixCell(f)},
		})
		printBoundedDivider(w, severityWidth, detailsWidth, assessmentWidth, fixWidth)
	}
}

func printBoundedDivider(w io.Writer, widths ...int) {
	totalWidth := 13
	for _, width := range widths {
		totalWidth += width
	}
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", totalWidth))
}

func printBoundedTableRow(w io.Writer, columns []tableColumn) int {
	wrapped := make([][]string, len(columns))
	maxLines := 0
	for i, column := range columns {
		wrapped[i] = wrapCell(column.value, column.width)
		if len(wrapped[i]) > maxLines {
			maxLines = len(wrapped[i])
		}
	}

	for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
		fmt.Fprint(w, "  | ")
		for colIdx, column := range columns {
			cell := ""
			if lineIdx < len(wrapped[colIdx]) {
				cell = wrapped[colIdx][lineIdx]
			}
			styled := cell
			if cell != "" && column.style != nil {
				styled = column.style(cell)
			}
			fmt.Fprint(w, padVisible(styled, column.width))
			if colIdx < len(columns)-1 {
				fmt.Fprint(w, " | ")
			} else {
				fmt.Fprintln(w, " |")
			}
		}
	}
	return maxLines
}

func severityLabel(sev core.Severity) string {
	value := strings.ToLower(sev.String())
	if value == "" {
		return "-"
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func styleSeverityLabel(sev core.Severity, clr color, text string) string {
	switch sev {
	case core.SeverityCritical:
		return clr.s(bold+brightRed, text)
	case core.SeverityHigh:
		return clr.s(bold+orange, text)
	case core.SeverityMedium:
		return clr.s(bold+yellow, text)
	case core.SeverityLow:
		return clr.s(bold+blue, text)
	default:
		return clr.s(gray, text)
	}
}

func sastFindingDetailsCell(f core.Finding) string {
	parts := []string{firstNonEmpty(f.RuleName, f.Title, f.RuleID, "Finding")}
	if location := formatFullLocation(f); location != "" && location != "(no file)" {
		parts = append(parts, "", location)
	}
	if description := inlineText(f.Description); description != "" && description != parts[0] {
		parts = append(parts, "", description)
	}
	if code := prefixedMultiline("Code: ", sastCodeLine(f)); code != "" {
		parts = append(parts, "", code)
	}
	return strings.Join(parts, "\n")
}

func sastAssessmentContextCell(f core.Finding) string {
	parts := make([]string, 0, 5)
	headerParts := make([]string, 0, 2)
	if verdict := strings.TrimSpace(f.Verdict); verdict != "" {
		headerParts = append(headerParts, verdict)
	}
	if confidence := strings.TrimSpace(f.Confidence); confidence != "" {
		headerParts = append(headerParts, fmt.Sprintf("[%s]", confidence))
	}
	header := strings.Join(headerParts, " ")
	if header == "" {
		header = "-"
	}
	parts = append(parts, header)
	if reason := inlineText(f.VerdictReason); reason != "" {
		parts = append(parts, "", reason)
	}
	if explanation := inlineText(f.Explanation); explanation != "" && explanation != inlineText(f.VerdictReason) {
		parts = append(parts, "", explanation)
	}
	return strings.Join(parts, "\n")
}

func sastTargetedFixCell(f core.Finding) string {
	parts := make([]string, 0, 4)
	if recommendation := strings.TrimSpace(f.FixSuggestion); recommendation != "" {
		parts = append(parts, "Recommendation: "+recommendation)
	}
	if code := strings.TrimSpace(f.FixCode); code != "" {
		if len(parts) > 0 {
			parts = append(parts, "")
		}
		parts = append(parts, prefixFirstLine("Code fix: ", code))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "\n")
}

func prefixedMultiline(prefix, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lines := strings.Split(value, "\n")
	prefixed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefixed = append(prefixed, prefix+line)
	}
	return strings.Join(prefixed, "\n")
}

func prefixFirstLine(prefix, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lines := strings.Split(value, "\n")
	lines[0] = prefix + strings.TrimSpace(lines[0])
	for i := 1; i < len(lines); i++ {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "\n")
}

func printFindingDetails(w io.Writer, clr color, f core.Finding) int {
	lines := 0
	if f.Verdict != "" {
		parts := []string{verdictColor(f.Verdict, clr)}
		if f.Confidence != "" {
			parts = append(parts, clr.s(gray, fmt.Sprintf("(confidence: %s)", f.Confidence)))
		}
		if reason := strings.TrimSpace(f.VerdictReason); reason != "" {
			parts = append(parts, clr.s(gray, reason))
		}
		lines += printDetailBlock(w, clr, strings.Join(parts, " "), clr.s(dim+cyan, "verdict"))
	}
	if f.Explanation != "" {
		lines += printDetailBlock(w, clr, clr.s(dim, f.Explanation), clr.s(dim+cyan, "why"))
	}
	if f.FixSuggestion != "" {
		lines += printDetailBlock(w, clr, clr.s(dim, f.FixSuggestion), clr.s(dim+cyan, "fix"))
	}
	if f.FixCode != "" {
		lines += printDetailBlock(w, clr, clr.s(dim, f.FixCode), clr.s(dim+cyan, "code"))
	}
	return lines
}

func printDetailBlock(w io.Writer, clr color, content, styledLabel string) int {
	const labelWidth = 8
	const detailWidth = 100

	lines := wrapCell(content, detailWidth)
	for i, line := range lines {
		labelText := ""
		if i == 0 {
			labelText = styledLabel
		}
		fmt.Fprintf(w, "  %s %s %s\n",
			clr.s(gray, "│"),
			padVisible(labelText, labelWidth),
			line,
		)
	}
	return len(lines)
}

func verdictColor(verdict string, clr color) string {
	switch verdict {
	case "TRUE_POSITIVE":
		return clr.s(bold+red, "🔺 TRUE_POSITIVE")
	case "FALSE_POSITIVE":
		return clr.s(bold+green, "🟢 FALSE_POSITIVE")
	default:
		return clr.s(gray, "● UNKNOWN")
	}
}

func summaryLine(w io.Writer, clr color, content string) {
	const width = 54
	pad := width - visibleLen(content)
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(w, "  %s%s%s%s\n",
		clr.s(cyan, "║"),
		content,
		strings.Repeat(" ", pad),
		clr.s(cyan, "║"),
	)
}

func printSummary(w io.Writer, clr color, result *core.ScanResult) {
	counts := make(map[core.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", clr.s(cyan, "╔══════════════════════════════════════════════════════╗"))
	summaryLine(w, clr, "")
	summaryLine(w, clr, fmt.Sprintf("  %s  total findings",
		clr.s(bold+white, fmt.Sprintf("%d", len(result.Findings))),
	))
	summaryLine(w, clr, fmt.Sprintf("  %s  %s  %s",
		clr.s(bold+brightRed, fmt.Sprintf("Critical %-3d", counts[core.SeverityCritical])),
		clr.s(bold+orange, fmt.Sprintf("High %-3d", counts[core.SeverityHigh])),
		clr.s(bold+yellow, fmt.Sprintf("Medium %-3d", counts[core.SeverityMedium])),
	))
	summaryLine(w, clr, fmt.Sprintf("  %s  %s",
		clr.s(bold+blue, fmt.Sprintf("Low %-3d", counts[core.SeverityLow])),
		clr.s(bold+gray, fmt.Sprintf("Info %-3d", counts[core.SeverityInfo])),
	))
	summaryLine(w, clr, fmt.Sprintf("  %s",
		clr.s(gray, fmt.Sprintf("duration: %s", result.Duration.Round(time.Millisecond))),
	))
	if result.SuppressedCount > 0 {
		summaryLine(w, clr, fmt.Sprintf("  %s",
			clr.s(gray, fmt.Sprintf("%d suppressed", result.SuppressedCount)),
		))
	}
	for _, desc := range result.MissingRequired {
		summaryLine(w, clr, fmt.Sprintf("  %s %s",
			clr.s(bold+yellow, "!"),
			clr.s(yellow, fmt.Sprintf("missing required: %s", trunc(desc, 44))),
		))
	}
	summaryLine(w, clr, "")
	fmt.Fprintf(w, "  %s\n\n", clr.s(cyan, "╚══════════════════════════════════════════════════════╝"))
}

func formatLocation(f core.Finding) string {
	if f.FilePath == "" {
		return "(no file)"
	}
	if f.StartLine > 0 {
		return fmt.Sprintf("%s:%d", truncPath(f.FilePath, 100), f.StartLine)
	}
	return truncPath(f.FilePath, 100)
}

func formatFullLocation(f core.Finding) string {
	if f.FilePath == "" {
		return "(no file)"
	}
	if f.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.FilePath, f.StartLine)
	}
	return f.FilePath
}

func formatCompactLocation(f core.Finding, maxLen int) string {
	location := formatFullLocation(f)
	if maxLen <= 0 {
		return location
	}
	return truncPath(location, maxLen)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func compactCell(value string, width int) string {
	value = inlineText(value)
	if width <= 0 || visibleLen(value) <= width {
		return value
	}
	return trunc(value, width)
}

func inlineText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.Join(strings.Fields(value), " ")
}

func sastSummaryText(f core.Finding) string {
	summary := firstNonEmpty(f.Description, f.RuleID, f.Title)
	summary = inlineText(summary)
	if summary == "" {
		return "-"
	}
	return summary
}

func hasSASTDetails(f core.Finding) bool {
	return f.Verdict != "" || f.Explanation != "" || f.FixSuggestion != "" || f.FixCode != ""
}

func sastVerdictCell(f core.Finding, clr color) string {
	parts := make([]string, 0, 3)
	if f.Verdict != "" {
		parts = append(parts, verdictColor(f.Verdict, clr))
	}
	if f.Confidence != "" {
		parts = append(parts, clr.s(gray, fmt.Sprintf("(confidence: %s)", f.Confidence)))
	}
	if reason := strings.TrimSpace(f.VerdictReason); reason != "" {
		parts = append(parts, clr.s(gray, reason))
	}
	lines := []string{strings.Join(parts, " ")}
	if explanation := inlineText(f.Explanation); explanation != "" {
		lines = append(lines, explanation)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func sastCodeCell(f core.Finding) string {
	parts := make([]string, 0, 2)
	if loc := formatFullLocation(f); loc != "" {
		parts = append(parts, loc)
	}
	if code := sastCodeLine(f); code != "" {
		parts = append(parts, code)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "\n")
}

func sastFixCell(f core.Finding) string {
	fix := strings.TrimSpace(f.FixSuggestion)
	if fix == "" {
		return "-"
	}
	return fix
}

func sastCodeLine(f core.Finding) string {
	if f.FilePath == "" || f.StartLine <= 0 {
		return ""
	}
	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if f.StartLine > len(lines) {
		return ""
	}
	line := strings.TrimSpace(lines[f.StartLine-1])
	if line == "" {
		return ""
	}
	parts := []string{line}
	if looksLikeContextLine(line) {
		for next := f.StartLine; next < len(lines); next++ {
			candidate := strings.TrimSpace(lines[next])
			if candidate == "" {
				continue
			}
			parts = append(parts, candidate)
			break
		}
	}
	return strings.Join(parts, "\n")
}

func looksLikeContextLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	return strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "if ") || strings.HasPrefix(line, "for ") || strings.HasSuffix(line, "{")
}

func printTableRow(w io.Writer, columns []tableColumn) int {
	wrapped := make([][]string, len(columns))
	maxLines := 0
	for i, column := range columns {
		wrapped[i] = wrapCell(column.value, column.width)
		if len(wrapped[i]) > maxLines {
			maxLines = len(wrapped[i])
		}
	}

	for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
		fmt.Fprint(w, "  ")
		for colIdx, column := range columns {
			cell := ""
			if lineIdx < len(wrapped[colIdx]) {
				cell = wrapped[colIdx][lineIdx]
			}
			styled := cell
			if cell != "" && column.style != nil {
				styled = column.style(cell)
			}
			fmt.Fprint(w, padVisible(styled, column.width))
			if colIdx < len(columns)-1 {
				fmt.Fprint(w, "  ")
			}
		}
		fmt.Fprintln(w)
	}
	return maxLines
}

func wrapCell(value string, width int) []string {
	value = strings.TrimSpace(value)
	if value == "" || width <= 0 {
		return []string{""}
	}

	lines := make([]string, 0)
	for _, rawLine := range strings.Split(value, "\n") {
		rawLine = strings.TrimSpace(rawLine)
		if rawLine == "" {
			lines = append(lines, "")
			continue
		}

		words := strings.Fields(rawLine)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}

		line := ""
		for _, word := range words {
			parts := wrapToken(word, width)
			for idx, part := range parts {
				if line == "" {
					line = part
					continue
				}
				if idx > 0 {
					lines = append(lines, line)
					line = part
					continue
				}
				if visibleLen(line+" "+part) <= width {
					line += " " + part
					continue
				}
				lines = append(lines, line)
				line = part
			}
		}
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func wrapToken(value string, width int) []string {
	if visibleLen(value) <= width || width <= 0 {
		return []string{value}
	}

	runes := []rune(value)
	lines := make([]string, 0, (len(runes)/width)+1)
	for len(runes) > 0 {
		if len(runes) <= width {
			lines = append(lines, string(runes))
			break
		}
		end := width
		split := preferredSplitIndex(runes, end)
		lines = append(lines, string(runes[:split]))
		runes = runes[split:]
	}
	return lines
}

func preferredSplitIndex(runes []rune, end int) int {
	for i := end; i > 0; i-- {
		switch runes[i-1] {
		case '/', '.', '_', '-', ':':
			return i
		}
	}
	return end
}

func padVisible(value string, width int) string {
	padding := width - visibleLen(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func trunc(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-2]) + ".."
}

func truncPath(path string, maxLen int) string {
	runes := []rune(path)
	if len(runes) <= maxLen || maxLen <= 3 {
		return path
	}
	return "..." + string(runes[len(runes)-maxLen+3:])
}
