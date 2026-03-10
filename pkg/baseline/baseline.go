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
	Suppress []SuppressEntry `yaml:"suppress"`
	Require  []RequireEntry  `yaml:"require"`
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
	if len(b.Suppress) == 0 && len(b.Require) == 0 {
		return findings, nil, 0
	}

	suppressSet := make(map[string]bool, len(b.Suppress))
	for _, e := range b.Suppress {
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
