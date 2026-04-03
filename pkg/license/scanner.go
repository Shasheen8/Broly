// Package license detects software licenses and checks them against a policy.
package license

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

type policy struct {
	allowed []string
	denied  []string
}

type detection struct {
	pkg      string
	license  string
	filePath string
}

type LicenseScanner struct {
	policy policy
}

func NewLicenseScanner() *LicenseScanner {
	return &LicenseScanner{}
}

func (s *LicenseScanner) Name() string        { return "license" }
func (s *LicenseScanner) Type() core.ScanType { return core.ScanTypeLicense }

func (s *LicenseScanner) Init(cfg *core.Config) error {
	s.policy = policy{
		allowed: cfg.AllowedLicenses,
		denied:  cfg.DeniedLicenses,
	}
	return nil
}

func (s *LicenseScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	if len(s.policy.allowed) == 0 && len(s.policy.denied) == 0 {
		return nil
	}

	for _, target := range paths {
		if ctx.Err() != nil {
			return nil
		}
		for _, d := range detectLicenses(target) {
			status := s.checkPolicy(d.license)

			var ruleID, severity string
			switch status {
			case "denied":
				ruleID = "broly.license.denied"
				severity = "HIGH"
			case "unknown":
				if len(s.policy.allowed) == 0 {
					continue
				}
				ruleID = "broly.license.unknown"
				severity = "MEDIUM"
			default:
				continue
			}

			sev := core.ParseSeverity(severity)
			f := core.Finding{
				Type:        core.ScanTypeLicense,
				RuleID:      ruleID,
				RuleName:    status + " license: " + d.license,
				Severity:    sev,
				Title:       fmt.Sprintf("%s license %s in %s", capitalize(status), d.license, d.pkg),
				Description: fmt.Sprintf("Package %s uses license %s which is %s by policy", d.pkg, d.license, status),
				FilePath:    d.filePath,
				StartLine:   1,
				Tags:        []string{"license", "policy"},
				Timestamp:   time.Now(),
			}
			f.ComputeFingerprint()
			select {
			case findings <- f:
			case <-ctx.Done():
				return nil
			}
		}
	}
	return nil
}

func (s *LicenseScanner) Close() error { return nil }

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *LicenseScanner) checkPolicy(lic string) string {
	for _, d := range s.policy.denied {
		if strings.EqualFold(d, lic) {
			return "denied"
		}
	}
	if len(s.policy.allowed) == 0 {
		return "allowed"
	}
	for _, a := range s.policy.allowed {
		if strings.EqualFold(a, lic) {
			return "allowed"
		}
	}
	return "unknown"
}

// licenseFiles are filenames that typically contain license text.
var licenseFiles = map[string]bool{
	"LICENSE": true, "LICENSE.md": true, "LICENSE.txt": true,
	"LICENCE": true, "LICENCE.md": true, "LICENCE.txt": true,
	"COPYING": true, "COPYING.md": true, "COPYING.txt": true,
}

// detectLicenses walks the target directory for LICENSE files and identifies the license type.
func detectLicenses(root string) []detection {
	var detections []detection
	seen := make(map[string]bool)

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		if !licenseFiles[d.Name()] {
			return nil
		}

		// Use parent directory as package name.
		rel, _ := filepath.Rel(root, path)
		pkg := filepath.Dir(rel)
		if pkg == "." {
			pkg = filepath.Base(root)
		}

		if seen[pkg] {
			return nil
		}
		seen[pkg] = true

		lic := identifyLicense(path)
		detections = append(detections, detection{
			pkg:      pkg,
			license:  lic,
			filePath: rel,
		})
		return nil
	})

	return detections
}

// identifyLicense reads a LICENSE file and identifies the license type by keyword matching.
func identifyLicense(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	var content strings.Builder
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() && lines < 50 {
		content.WriteString(sc.Text())
		content.WriteByte('\n')
		lines++
	}
	text := strings.ToLower(content.String())

	// Match in order of specificity.
	switch {
	case strings.Contains(text, "apache license") && strings.Contains(text, "version 2"):
		return "Apache-2.0"
	case strings.Contains(text, "mit license") || (strings.Contains(text, "permission is hereby granted") && strings.Contains(text, "without restriction")):
		return "MIT"
	case strings.Contains(text, "bsd 3-clause") || (strings.Contains(text, "redistribution") && strings.Contains(text, "neither the name")):
		return "BSD-3-Clause"
	case strings.Contains(text, "bsd 2-clause") || (strings.Contains(text, "redistribution") && !strings.Contains(text, "neither the name") && strings.Contains(text, "binary form")):
		return "BSD-2-Clause"
	case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 3"):
		return "GPL-3.0"
	case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 2"):
		return "GPL-2.0"
	case strings.Contains(text, "gnu lesser general public license") || strings.Contains(text, "gnu library general"):
		return "LGPL"
	case strings.Contains(text, "gnu affero general public license"):
		return "AGPL-3.0"
	case strings.Contains(text, "mozilla public license") && strings.Contains(text, "version 2"):
		return "MPL-2.0"
	case strings.Contains(text, "isc license") || (strings.Contains(text, "permission to use, copy, modify") && strings.Contains(text, "isc")):
		return "ISC"
	case strings.Contains(text, "unlicense") || strings.Contains(text, "this is free and unencumbered"):
		return "Unlicense"
	case strings.Contains(text, "creative commons") && strings.Contains(text, "cc0"):
		return "CC0-1.0"
	case strings.Contains(text, "eclipse public license"):
		return "EPL"
	default:
		return "unknown"
	}
}
