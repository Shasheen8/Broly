package core

import (
	"crypto/sha256"
	"fmt"
	"time"
)

type ScanType string

const (
	ScanTypeSAST    ScanType = "sast"
	ScanTypeSCA     ScanType = "sca"
	ScanTypeSecrets ScanType = "secrets"
)

type Finding struct {
	ID          string   `json:"id"`
	Type        ScanType `json:"type"`
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`

	FilePath    string `json:"file_path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	Snippet     string `json:"snippet,omitempty"`

	PackageName    string  `json:"package_name,omitempty"`
	PackageVersion string  `json:"package_version,omitempty"`
	Ecosystem      string  `json:"ecosystem,omitempty"`
	FixedVersion   string  `json:"fixed_version,omitempty"`
	CVE            string  `json:"cve,omitempty"`
	CVSSScore      float64 `json:"cvss_score,omitempty"`
	Advisory       string  `json:"advisory_url,omitempty"`

	Redacted string  `json:"redacted,omitempty"`
	Entropy  float64 `json:"entropy,omitempty"`

	CWE         []string  `json:"cwe,omitempty"`
	References  []string  `json:"references,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Timestamp   time.Time `json:"timestamp"`
}

// ComputeFingerprint sets a deduplication hash. Changes when file path or line changes.
func (f *Finding) ComputeFingerprint() {
	data := fmt.Sprintf("%s:%s:%s:%s:%d",
		f.Type, f.RuleID, f.FilePath, f.Snippet, f.StartLine,
	)
	hash := sha256.Sum256([]byte(data))
	f.Fingerprint = fmt.Sprintf("%x", hash[:])
}

type ScanResult struct {
	Findings        []Finding     `json:"findings"`
	Metrics         ScanMetrics   `json:"metrics"`
	Duration        time.Duration `json:"duration_ms"`
	ScanTypes       []ScanType    `json:"scan_types"`
	SuppressedCount int           `json:"suppressed_count,omitempty"`
	MissingRequired []string      `json:"missing_required,omitempty"`
}

type ScanMetrics struct {
	FilesScanned  int64 `json:"files_scanned"`
	FilesSkipped  int64 `json:"files_skipped"`
	TotalBytes    int64 `json:"total_bytes"`
	FindingsCount int   `json:"findings_count"`
	RulesLoaded   int   `json:"rules_loaded"`
}
