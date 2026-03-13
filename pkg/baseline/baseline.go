package baseline

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Shasheen8/Broly/pkg/core"
)

type SuppressEntry struct {
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
}

type RequireEntry struct {
	Fingerprint string `yaml:"fingerprint,omitempty"`
	RuleID      string `yaml:"rule_id,omitempty"`
	File        string `yaml:"file,omitempty"`
	Reason      string `yaml:"reason"`
}

type Baseline struct {
	Suppressions []SuppressEntry `yaml:"suppress"`
	Require      []RequireEntry  `yaml:"require"`
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{}, nil
		}
		return nil, err
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Baseline) Apply(findings []core.Finding) (filtered []core.Finding, missing []string, suppressed int) {
	if len(b.Suppressions) == 0 && len(b.Require) == 0 {
		return findings, nil, 0
	}

	suppressSet := make(map[string]bool, len(b.Suppressions))
	for _, e := range b.Suppressions {
		if e.Fingerprint != "" {
			suppressSet[e.Fingerprint] = true
		}
	}

	for _, f := range findings {
		if suppressSet[f.Fingerprint] {
			suppressed++
			continue
		}
		filtered = append(filtered, f)
	}

	for _, req := range b.Require {
		found := false
		for _, f := range findings { // check against full original set
			if matchesRequire(f, req) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, requireDesc(req))
		}
	}

	return filtered, missing, suppressed
}

// CheckRequired returns descriptions of required findings that are absent from findings.
func (b *Baseline) CheckRequired(findings []core.Finding) []string {
	var missing []string
	for _, req := range b.Require {
		found := false
		for _, f := range findings {
			if matchesRequire(f, req) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, requireDesc(req))
		}
	}
	return missing
}

// Suppress removes findings that match a suppress entry. Returns filtered slice and count.
func (b *Baseline) Suppress(findings []core.Finding) ([]core.Finding, int) {
	if len(b.Suppressions) == 0 {
		return findings, 0
	}
	suppressSet := make(map[string]bool, len(b.Suppressions))
	for _, e := range b.Suppressions {
		if e.Fingerprint != "" {
			suppressSet[e.Fingerprint] = true
		}
	}
	var out []core.Finding
	var count int
	for _, f := range findings {
		if suppressSet[f.Fingerprint] {
			count++
			continue
		}
		out = append(out, f)
	}
	return out, count
}

func matchesRequire(f core.Finding, req RequireEntry) bool {
	if req.Fingerprint != "" {
		return f.Fingerprint == req.Fingerprint
	}
	if req.RuleID == "" {
		return false
	}
	if !strings.EqualFold(f.RuleID, req.RuleID) {
		return false
	}
	if req.File != "" && !strings.Contains(f.FilePath, req.File) {
		return false
	}
	return true
}

func requireDesc(req RequireEntry) string {
	if req.Reason != "" {
		return req.Reason
	}
	if req.Fingerprint != "" {
		short := req.Fingerprint
		if len(short) > 8 {
			short = short[:8] + "..."
		}
		return "fingerprint " + short
	}
	desc := req.RuleID
	if req.File != "" {
		desc += " in " + req.File
	}
	return desc
}
