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

	for _, scanType := range []core.ScanType{core.ScanTypeSecrets, core.ScanTypeSCA, core.ScanTypeSAST} {
		findings, ok := byScanType[scanType]
		if !ok {
			continue
		}
		label := scanTypeLabel(scanType)
		fmt.Fprintf(w, "\n  %s %s\n\n",
			clr.s(cyan+bold, fmt.Sprintf("▸ %s", label)),
			clr.s(gray, fmt.Sprintf("(%d finding%s)", len(findings), plural(len(findings)))),
		)
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
	case core.ScanTypeSAST:
		printSASTTable(w, clr, findings)
	}
}

func printSecretsTable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-12s %-32s %-42s %s", "SEVERITY", "RULE", "FILE", "REDACTED"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 110)))
	for _, f := range findings {
		location := fmt.Sprintf("%s:%d", truncPath(f.FilePath, 40), f.StartLine)
		fmt.Fprintf(w, "  %-12s %-32s %-42s %s\n",
			severityColor(f.Severity, clr),
			trunc(f.RuleName, 30),
			clr.s(dim, trunc(location, 40)),
			clr.s(gray, trunc(f.Redacted, 30)),
		)
		if f.Verdict != "" {
			fmt.Fprintf(w, "  %s %s\n",
				verdictColor(f.Verdict, clr),
				clr.s(gray, trunc(f.VerdictReason, 90)),
			)
		}
	}
}

func printSCATable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-12s %-22s %-18s %-14s %-16s %s", "SEVERITY", "VULN ID", "PACKAGE", "VERSION", "FIXED", "ECOSYSTEM"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 110)))
	for _, f := range findings {
		fixed := f.FixedVersion
		if fixed == "" {
			fixed = clr.s(red, "no fix")
		} else {
			fixed = clr.s(green, fixed)
		}
		fmt.Fprintf(w, "  %-12s %-22s %-18s %-14s %-16s %s\n",
			severityColor(f.Severity, clr),
			clr.s(cyan, trunc(f.RuleID, 20)),
			clr.s(white, trunc(f.PackageName, 16)),
			clr.s(gray, trunc(f.PackageVersion, 12)),
			fixed,
			clr.s(dim, f.Ecosystem),
		)
		if f.Verdict != "" {
			fmt.Fprintf(w, "  %s %s\n",
				verdictColor(f.Verdict, clr),
				clr.s(gray, trunc(f.VerdictReason, 90)),
			)
		}
	}
}

func printSASTTable(w io.Writer, clr color, findings []core.Finding) {
	hdr := clr.s(bold+gray, fmt.Sprintf("  %-12s %-32s %-42s %s", "SEVERITY", "ISSUE", "FILE", "DESCRIPTION"))
	fmt.Fprintln(w, hdr)
	fmt.Fprintf(w, "  %s\n", clr.s(gray, strings.Repeat("─", 110)))
	for _, f := range findings {
		location := fmt.Sprintf("%s:%d", truncPath(f.FilePath, 40), f.StartLine)
		fmt.Fprintf(w, "  %-12s %-32s %-42s %s\n",
			severityColor(f.Severity, clr),
			trunc(f.RuleName, 30),
			clr.s(dim, trunc(location, 40)),
			clr.s(gray, trunc(f.Title, 30)),
		)
		if f.Verdict != "" {
			fmt.Fprintf(w, "  %s %s\n",
				verdictColor(f.Verdict, clr),
				clr.s(gray, trunc(f.VerdictReason, 90)),
			)
		}
		if f.FixSuggestion != "" {
			fmt.Fprintf(w, "  %s\n", clr.s(dim+cyan, "  fix:"))
			for _, line := range strings.Split(f.FixSuggestion, "\n") {
				fmt.Fprintf(w, "  %s\n", clr.s(dim, "    "+line))
			}
		}
	}
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
	summaryLine(w, clr, fmt.Sprintf("  %s  %s  %s  %s",
		clr.s(bold+brightRed, fmt.Sprintf("Critical %-3d", counts[core.SeverityCritical])),
		clr.s(bold+orange, fmt.Sprintf("High %-3d", counts[core.SeverityHigh])),
		clr.s(bold+yellow, fmt.Sprintf("Medium %-3d", counts[core.SeverityMedium])),
		clr.s(bold+blue, fmt.Sprintf("Low %-3d", counts[core.SeverityLow])),
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
