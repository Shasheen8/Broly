package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

type TableFormatter struct{}

func (f *TableFormatter) Name() string { return "table" }

func (f *TableFormatter) Format(w io.Writer, result *core.ScanResult) error {
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "\n  No findings detected. Clean scan!")
		return nil
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity != result.Findings[j].Severity {
			return result.Findings[i].Severity > result.Findings[j].Severity
		}
		return result.Findings[i].FilePath < result.Findings[j].FilePath
	})

	byScanType := make(map[core.ScanType][]core.Finding)
	for _, f := range result.Findings {
		byScanType[f.Type] = append(byScanType[f.Type], f)
	}

	printBanner(w)

	for _, scanType := range []core.ScanType{core.ScanTypeSecrets, core.ScanTypeSCA, core.ScanTypeSAST} {
		findings, ok := byScanType[scanType]
		if !ok {
			continue
		}

		fmt.Fprintf(w, "\n  === %s Findings (%d) ===\n\n", strings.ToUpper(string(scanType)), len(findings))
		printScanTypeTable(w, scanType, findings)
	}

	printSummary(w, result)
	return nil
}

func printBanner(w io.Writer) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║          BROLY SECURITY SCAN             ║")
	fmt.Fprintln(w, "  ║      Berserker Product Security          ║")
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════╝")
}

func printScanTypeTable(w io.Writer, scanType core.ScanType, findings []core.Finding) {
	switch scanType {
	case core.ScanTypeSecrets:
		printSecretsTable(w, findings)
	case core.ScanTypeSCA:
		printSCATable(w, findings)
	case core.ScanTypeSAST:
		printSASTTable(w, findings)
	}
}

func printSecretsTable(w io.Writer, findings []core.Finding) {
	fmt.Fprintf(w, "  %-10s %-30s %-40s %s\n", "SEVERITY", "RULE", "FILE", "REDACTED")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 110))
	for _, f := range findings {
		location := fmt.Sprintf("%s:%d", truncPath(f.FilePath, 38), f.StartLine)
		fmt.Fprintf(w, "  %-10s %-30s %-40s %s\n",
			f.Severity.String(),
			trunc(f.RuleName, 28),
			location,
			trunc(f.Redacted, 30),
		)
	}
}

func printSCATable(w io.Writer, findings []core.Finding) {
	fmt.Fprintf(w, "  %-10s %-20s %-15s %-12s %-15s %s\n",
		"SEVERITY", "VULN ID", "PACKAGE", "VERSION", "FIXED", "ECOSYSTEM")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 110))
	for _, f := range findings {
		fixed := f.FixedVersion
		if fixed == "" {
			fixed = "no fix"
		}
		fmt.Fprintf(w, "  %-10s %-20s %-15s %-12s %-15s %s\n",
			f.Severity.String(),
			trunc(f.RuleID, 18),
			trunc(f.PackageName, 13),
			trunc(f.PackageVersion, 10),
			trunc(fixed, 13),
			f.Ecosystem,
		)
	}
}

func printSASTTable(w io.Writer, findings []core.Finding) {
	fmt.Fprintf(w, "  %-10s %-30s %-40s %s\n", "SEVERITY", "RULE", "FILE", "DESCRIPTION")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 110))
	for _, f := range findings {
		location := fmt.Sprintf("%s:%d", truncPath(f.FilePath, 38), f.StartLine)
		fmt.Fprintf(w, "  %-10s %-30s %-40s %s\n",
			f.Severity.String(),
			trunc(f.RuleName, 28),
			location,
			trunc(f.Title, 30),
		)
	}
}

func printSummary(w io.Writer, result *core.ScanResult) {
	counts := make(map[core.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  ┌─────────────────────────────────────────┐")
	fmt.Fprintf(w, "  │  Total Findings: %-24d│\n", len(result.Findings))
	fmt.Fprintf(w, "  │  Critical: %-6d  High: %-6d           │\n", counts[core.SeverityCritical], counts[core.SeverityHigh])
	fmt.Fprintf(w, "  │  Medium:   %-6d  Low:  %-6d           │\n", counts[core.SeverityMedium], counts[core.SeverityLow])
	fmt.Fprintf(w, "  │  Scan Duration: %-25s│\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintln(w, "  └─────────────────────────────────────────┘")
	fmt.Fprintln(w, "")
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
