package core

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"
)

type ScanType string

const (
	ScanTypeSAST       ScanType = "sast"
	ScanTypeSCA        ScanType = "sca"
	ScanTypeSecrets    ScanType = "secrets"
	ScanTypeDockerfile ScanType = "dockerfile"
	ScanTypeContainer  ScanType = "container"
	ScanTypeLicense    ScanType = "license"
)

type Finding struct {
	ID            string   `json:"id"`
	Type          ScanType `json:"type"`
	RuleID        string   `json:"rule_id"`
	RuleName      string   `json:"rule_name"`
	Severity      Severity `json:"severity"`
	PriorityScore int      `json:"priority_score,omitempty"`
	Confidence    string   `json:"confidence,omitempty"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`

	FilePath     string `json:"file_path"`
	ArtifactPath string `json:"artifact_path,omitempty"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	StartColumn  int    `json:"start_column,omitempty"`
	EndColumn    int    `json:"end_column,omitempty"`
	Snippet      string `json:"snippet,omitempty"`

	PackageName    string  `json:"package_name,omitempty"`
	PackageVersion string  `json:"package_version,omitempty"`
	Ecosystem      string  `json:"ecosystem,omitempty"`
	FixedVersion   string  `json:"fixed_version,omitempty"`
	CVE            string  `json:"cve,omitempty"`
	CVSSScore      float64 `json:"cvss_score,omitempty"`

	Redacted string  `json:"redacted,omitempty"`
	Entropy  float64 `json:"entropy,omitempty"`

	ImageDigest string `json:"image_digest,omitempty"`
	LayerDigest string `json:"layer_digest,omitempty"`
	LayerIndex  int    `json:"layer_index,omitempty"`
	BaseImage   string `json:"base_image,omitempty"`

	CWE         []string  `json:"cwe,omitempty"`
	References  []string  `json:"references,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Timestamp   time.Time `json:"timestamp"`

	Verdict       string `json:"verdict,omitempty"`        // TRUE_POSITIVE, FALSE_POSITIVE, UNKNOWN
	VerdictReason string `json:"verdict_reason,omitempty"` // one-sentence explanation
	FixSuggestion string `json:"fix_suggestion,omitempty"` // minimal targeted remediation guidance
	FixCode       string `json:"fix_code,omitempty"`       // concrete code fix snippet from LLM
	Explanation   string `json:"explanation,omitempty"`
}

// FileContext returns up to radius lines on each side of lineNum, with line numbers.
func FileContext(path string, lineNum, radius int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	start := lineNum - radius - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + radius
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		fmt.Fprintf(&sb, "%4d  %s\n", i+1, lines[i])
	}
	return sb.String()
}

// FileContextSafe returns up to radius lines on each side of startLine, redacting all lines
// from startLine through endLine inclusive (covers multiline secrets like PEM blocks).
func FileContextSafe(path string, startLine, endLine, radius int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if endLine < startLine {
		endLine = startLine
	}
	winStart := startLine - radius - 1
	if winStart < 0 {
		winStart = 0
	}
	winEnd := endLine + radius
	if winEnd > len(lines) {
		winEnd = len(lines)
	}
	var sb strings.Builder
	for i := winStart; i < winEnd; i++ {
		content := lines[i]
		lineNum := i + 1
		if lineNum >= startLine && lineNum <= endLine {
			content = "<content redacted>"
		}
		fmt.Fprintf(&sb, "%4d  %s\n", lineNum, content)
	}
	return sb.String()
}

// ComputePriorityScore sets a weighted priority score based on sec-context research.
// Formula: (Frequency × 2) + (Severity × 2) + Detectability
// Higher score = higher priority to fix.
func (f *Finding) ComputePriorityScore() {
	// Severity: map to 1-10 scale.
	var sevScore int
	switch f.Severity {
	case SeverityCritical:
		sevScore = 10
	case SeverityHigh:
		sevScore = 8
	case SeverityMedium:
		sevScore = 5
	case SeverityLow:
		sevScore = 3
	default:
		sevScore = 1
	}

	// Frequency and detectability: derived from vulnerability class and detection method tags.
	freqScore := 5
	detectScore := 5
	for _, tag := range f.Tags {
		switch tag {
		case "injection", "xss":
			freqScore = 9
		case "secrets":
			freqScore = 8
		case "crypto":
			freqScore = 6
		case "config":
			freqScore = 4
		case "prefilter":
			detectScore = 8
		case "ai":
			detectScore = 4
		}
	}

	f.PriorityScore = (freqScore * 2) + (sevScore * 2) + detectScore
}

// ComputeFingerprint sets a deduplication hash. Changes when file path or line changes.
// For secrets findings, always uses the redacted value so fingerprints are stable
// regardless of whether --no-redact is set.
func (f *Finding) ComputeFingerprint() {
	var data string
	switch f.Type {
	case ScanTypeSCA:
		data = fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			f.Type, f.RuleID, f.PackageName, f.PackageVersion, f.Ecosystem, f.FilePath,
		)
	case ScanTypeContainer:
		data = fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
			f.Type, f.RuleID, f.PackageName, f.PackageVersion, f.Ecosystem, f.FilePath, f.LayerDigest, f.ArtifactPath,
		)
	case ScanTypeSecrets:
		snippet := f.Redacted
		if snippet == "" {
			snippet = f.Snippet
		}
		data = fmt.Sprintf("%s:%s:%s:%s:%d",
			f.Type, f.RuleID, f.FilePath, snippet, f.StartLine,
		)
	default:
		data = fmt.Sprintf("%s:%s:%s:%s:%d",
			f.Type, f.RuleID, f.FilePath, f.Snippet, f.StartLine,
		)
	}
	hash := sha256.Sum256([]byte(data))
	f.Fingerprint = fmt.Sprintf("%x", hash[:])
}

type ScanResult struct {
	Findings        []Finding     `json:"findings"`
	Metrics         ScanMetrics   `json:"metrics"`
	Duration        time.Duration `json:"duration_ns"`
	ScanTypes       []ScanType    `json:"scan_types"`
	SuppressedCount int           `json:"suppressed_count,omitempty"`
	MissingRequired []string      `json:"missing_required,omitempty"`
}

type ScanMetrics struct {
	FindingsCount int `json:"findings_count"`
}
