// Package sbom generates Software Bill of Materials in CycloneDX and SPDX formats.
package sbom

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

var ecosystems = []string{
	"go", "python", "javascript", "ruby", "rust", "java", "php",
	"dotnet", "dart", "cpp", "haskell", "elixir", "erlang", "r",
	"swift", "lua", "nim", "ocaml", "julia", "perl",
}

// Component represents a single package in the SBOM.
type Component struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
}

// Result holds the SBOM data.
type Result struct {
	Tool       string
	Version    string
	Timestamp  time.Time
	Components []Component
}

// Generate extracts all packages from the given paths and returns an SBOM result.
func Generate(ctx context.Context, paths []string, toolVersion string) (*Result, error) {
	var extractors []filesystem.Extractor
	for _, eco := range ecosystems {
		exts, err := list.ExtractorsFromName(eco, &cpb.PluginConfig{})
		if err != nil {
			continue
		}
		extractors = append(extractors, exts...)
	}

	var allPkgs []*extractor.Package
	for _, target := range paths {
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			continue
		}

		inv, _, err := filesystem.Run(ctx, &filesystem.Config{
			Extractors: extractors,
			ScanRoots:  []*scalibrfs.ScanRoot{{Path: target, FS: scalibrfs.DirFS(target)}},
			Stats:      stats.NoopCollector{},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: sbom extraction in %s: %v\n", target, err)
			continue
		}
		allPkgs = append(allPkgs, inv.Packages...)
	}

	// Deduplicate by name+version+ecosystem.
	seen := make(map[string]bool)
	var components []Component
	for _, p := range allPkgs {
		eco := p.Ecosystem().String()
		key := p.Name + "@" + p.Version + "@" + eco
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, Component{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: eco,
			PURL:      buildPURL(p.Name, p.Version, eco),
		})
	}

	return &Result{
		Tool:       "broly",
		Version:    toolVersion,
		Timestamp:  time.Now(),
		Components: components,
	}, nil
}

func buildPURL(name, version, ecosystem string) string {
	eco := strings.ToLower(ecosystem)
	switch {
	case strings.Contains(eco, "go"):
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case strings.Contains(eco, "pypi") || strings.Contains(eco, "python"):
		return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
	case strings.Contains(eco, "npm") || strings.Contains(eco, "javascript"):
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case strings.Contains(eco, "rubygems") || strings.Contains(eco, "ruby"):
		return fmt.Sprintf("pkg:gem/%s@%s", name, version)
	case strings.Contains(eco, "cargo") || strings.Contains(eco, "rust"):
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case strings.Contains(eco, "maven") || strings.Contains(eco, "java"):
		return fmt.Sprintf("pkg:maven/%s@%s", name, version)
	case strings.Contains(eco, "packagist") || strings.Contains(eco, "php"):
		return fmt.Sprintf("pkg:composer/%s@%s", name, version)
	case strings.Contains(eco, "nuget") || strings.Contains(eco, "dotnet"):
		return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
	case strings.Contains(eco, "cpan") || strings.Contains(eco, "perl"):
		return fmt.Sprintf("pkg:cpan/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}
