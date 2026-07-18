package core

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
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
	ScanTypeWorkflow   ScanType = "workflow"
)

func (t ScanType) Label() string {
	switch t {
	case ScanTypeSecrets:
		return "SECRETS"
	case ScanTypeSCA:
		return "SCA"
	case ScanTypeSAST:
		return "SAST"
	case ScanTypeWorkflow:
		return "GH Actions"
	case ScanTypeDockerfile:
		return "DOCKERFILE"
	case ScanTypeContainer:
		return "CONTAINER"
	case ScanTypeLicense:
		return "LICENSE"
	default:
		return strings.ToUpper(string(t))
	}
}

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

	CWE              []string  `json:"cwe,omitempty"`
	References       []string  `json:"references,omitempty"`
	Tags             []string  `json:"tags,omitempty"`
	Fingerprint      string    `json:"fingerprint"`
	OrgMatchKey      string    `json:"org_match_key,omitempty"`
	BaselineMatchKey string    `json:"baseline_match_key,omitempty"`
	UsageDeltaKey    string    `json:"usage_delta_key,omitempty"`
	Timestamp        time.Time `json:"timestamp"`

	Verdict       string `json:"verdict,omitempty"`        // TRUE_POSITIVE, FALSE_POSITIVE, (empty = not triaged)
	VerdictReason string `json:"verdict_reason,omitempty"` // one-sentence explanation
	FixSuggestion string `json:"fix_suggestion,omitempty"` // minimal targeted remediation guidance
	FixCode       string `json:"fix_code,omitempty"`       // concrete code fix snippet from LLM
	Explanation   string `json:"explanation,omitempty"`

	AdversarialVerdict string `json:"adversarial_verdict,omitempty"` // CONFIRMED, DISPUTED, FALSIFIED
	AdversarialReason  string `json:"adversarial_reason,omitempty"`

	ChainID     string   `json:"chain_id,omitempty"`
	ChainedFrom []string `json:"chained_from,omitempty"`
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

// ComputeIdentityKeys populates all currently supported finding identities.
func (f *Finding) ComputeIdentityKeys() {
	f.ComputeFingerprint()
	f.ComputeOrgMatchKey()
	f.ComputeBaselineMatchKey()
	f.ComputeUsageDeltaKey()
}

// ComputeOrgMatchKey sets a path-independent hash for cross-repo policy decisions.
// Unsupported finding types keep an empty OrgMatchKey in v1.
func (f *Finding) ComputeOrgMatchKey() {
	var parts []string
	switch f.Type {
	case ScanTypeSCA:
		parts = requiredKeyParts(
			string(f.Type),
			f.RuleID,
			f.PackageName,
			f.PackageVersion,
			f.Ecosystem,
		)
	case ScanTypeContainer:
		parts = requiredKeyParts(
			string(f.Type),
			f.RuleID,
			f.PackageName,
			f.PackageVersion,
			f.Ecosystem,
		)
	default:
		f.OrgMatchKey = ""
		return
	}
	if parts == nil {
		f.OrgMatchKey = ""
		return
	}

	hash := sha256.Sum256([]byte(strings.Join(parts, ":")))
	f.OrgMatchKey = fmt.Sprintf("%x", hash[:])
}

// ComputeBaselineMatchKey sets a scanner-specific key for repo posture
// reconciliation across scans. It is intentionally separate from Fingerprint,
// which remains repo-local and path/line sensitive for suppressions.
func (f *Finding) ComputeBaselineMatchKey() {
	var parts []string
	switch f.Type {
	case ScanTypeSCA:
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			f.RuleID,
			f.PackageName,
			f.PackageVersion,
			f.Ecosystem,
			normalizePathKeyPart(f.FilePath),
		)
	case ScanTypeSecrets:
		secretValue := strings.TrimSpace(f.Redacted)
		if secretValue == "" {
			secretValue = strings.TrimSpace(f.Snippet)
		}
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			f.RuleID,
			normalizePathKeyPart(f.FilePath),
			rawHashKeyPart(secretValue),
		)
	case ScanTypeContainer:
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			f.RuleID,
			f.PackageName,
			f.PackageVersion,
			f.Ecosystem,
			normalizePathKeyPart(f.FilePath),
			normalizePathKeyPart(f.ArtifactPath),
		)
	case ScanTypeSAST, ScanTypeDockerfile:
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			stableSASTFamily(*f),
			normalizePathKeyPart(f.FilePath),
			lineBucketKeyPart(f.StartLine),
		)
	case ScanTypeWorkflow:
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			stableWorkflowFamily(*f),
			normalizePathKeyPart(f.FilePath),
			lineBucketKeyPart(f.StartLine),
		)
	case ScanTypeLicense:
		parts = requiredKeyParts(
			"v1",
			string(f.Type),
			f.RuleID,
			normalizePathKeyPart(f.FilePath),
		)
	default:
		f.BaselineMatchKey = ""
		return
	}
	if parts == nil {
		f.BaselineMatchKey = ""
		return
	}
	f.BaselineMatchKey = hashKeyParts(parts)
}

// ComputeUsageDeltaKey sets a PR-time exposure key used to answer whether a PR
// made a baseline-known dependency risk more real. It is distinct from
// BaselineMatchKey so inventory and usage semantics can diverge.
func (f *Finding) ComputeUsageDeltaKey() {
	var parts []string
	switch f.Type {
	case ScanTypeSCA:
		parts = requiredKeyParts(
			"v1",
			"usage-delta",
			string(f.Type),
			f.RuleID,
			f.PackageName,
			f.PackageVersion,
			f.Ecosystem,
		)
	default:
		f.UsageDeltaKey = ""
		return
	}
	if parts == nil {
		f.UsageDeltaKey = ""
		return
	}
	f.UsageDeltaKey = hashKeyParts(parts)
}

func requiredKeyParts(values ...string) []string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			return nil
		}
		parts = append(parts, normalized)
	}
	return parts
}

func hashKeyParts(parts []string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", hash[:])
}

func rawHashKeyPart(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(trimmed))
	return fmt.Sprintf("%x", hash[:])
}

func normalizePathKeyPart(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	return strings.ReplaceAll(path, "\\", "/")
}

func lineBucketKeyPart(line int) string {
	if line <= 0 {
		return "0"
	}
	// Coarse buckets tolerate modest edits above or below the finding while
	// Fingerprint remains the exact path/line-sensitive identity.
	return fmt.Sprintf("%d", ((line-1)/20)+1)
}

func stableWorkflowFamily(f Finding) string {
	if normalized := strings.ToLower(strings.TrimSpace(f.RuleID)); normalized != "" {
		return normalized
	}
	return stableSASTFamily(f)
}

func stableSASTFamily(f Finding) string {
	for _, cwe := range f.CWE {
		if normalized := strings.ToLower(strings.TrimSpace(cwe)); normalized != "" {
			return normalized
		}
	}
	if strings.HasPrefix(f.RuleID, "broly.prefilter.") {
		return strings.ToLower(strings.TrimSpace(f.RuleID))
	}
	for _, tag := range f.Tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		switch normalized {
		case "", "sast", "ai", "dockerfile", "prefilter":
			continue
		default:
			return normalized
		}
	}
	if normalized := strings.ToLower(strings.TrimSpace(f.RuleID)); normalized != "" {
		return normalized
	}
	if f.Type == ScanTypeDockerfile {
		return "dockerfile"
	}
	return strings.ToLower(strings.TrimSpace(f.Severity.String()))
}

func (f Finding) IsMaliciousPackage() bool {
	return strings.HasPrefix(f.RuleID, "sca.malicious.")
}

type ExploitChain struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Fingerprints []string `json:"fingerprints"`
	Steps        []string `json:"steps"`
	Narrative    string   `json:"narrative"`
	Severity     Severity `json:"severity"`
	Derived      bool     `json:"derived_severity"`
}

type ScanResult struct {
	Findings        []Finding        `json:"findings"`
	ExploitChains   []ExploitChain   `json:"exploit_chains,omitempty"`
	Metrics         ScanMetrics      `json:"metrics"`
	Duration        time.Duration    `json:"duration_ns"`
	ScanTypes       []ScanType       `json:"scan_types"`
	SuppressedCount int              `json:"suppressed_count,omitempty"`
	MissingRequired []string         `json:"missing_required,omitempty"`
	SBOM            *SBOMArtifactRef `json:"sbom,omitempty"`
	SBOMCycloneDX   []byte           `json:"-"`
}

type SBOMArtifactRef struct {
	ComponentCount int    `json:"component_count"`
	Format         string `json:"format"`
	CycloneDXKey   string `json:"cyclonedx_key,omitempty"`
}

type ScanMetrics struct {
	FindingsCount    int                      `json:"findings_count"`
	ScannerDurations map[string]time.Duration `json:"scanner_durations_ns,omitempty"`
}
