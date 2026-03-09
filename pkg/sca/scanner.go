// Package sca adapts osv-scalibr + osv.dev to Broly's core.Scanner interface.
package sca

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

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"

	"github.com/Shasheen8/Broly/pkg/core"
)

var ecosystems = []string{
	"go", "python", "javascript", "ruby", "rust", "java", "php",
	"dotnet", "dart", "cpp", "haskell", "elixir", "erlang", "r",
	"swift", "lua", "nim", "ocaml", "julia",
}

type SCAScanner struct {
	osvClient  *osvdev.OSVClient
	extractors []filesystem.Extractor
	offline    bool
}

func NewSCAScanner() *SCAScanner {
	return &SCAScanner{}
}

func (s *SCAScanner) Name() string       { return "sca" }
func (s *SCAScanner) Type() core.ScanType { return core.ScanTypeSCA }

func (s *SCAScanner) Init(cfg *core.Config) error {
	s.offline = cfg.Offline
	s.osvClient = osvdev.DefaultClient()
	s.osvClient.Config.UserAgent = "broly-sca/1.0"

	var extractors []filesystem.Extractor
	for _, eco := range ecosystems {
		exts, err := list.ExtractorsFromName(eco, &cpb.PluginConfig{})
		if err != nil {
			continue
		}
		extractors = append(extractors, exts...)
	}
	s.extractors = extractors
	return nil
}

func (s *SCAScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	for _, target := range paths {
		if ctx.Err() != nil {
			return nil
		}

		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			continue
		}

		inv, _, err := filesystem.Run(ctx, &filesystem.Config{
			Extractors: s.extractors,
			ScanRoots:  []*scalibrfs.ScanRoot{{Path: target, FS: scalibrfs.DirFS(target)}},
			Stats:      stats.NoopCollector{},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: sca extraction in %s: %v\n", target, err)
			continue
		}

		pkgs := inv.Packages
		if len(pkgs) == 0 || s.offline {
			continue
		}

		queries := make([]*api.Query, len(pkgs))
		for i, pkg := range pkgs {
			eco := pkg.Ecosystem()
			queries[i] = &api.Query{
				Package: &osvschema.Package{
					Name:      pkg.Name,
					Ecosystem: eco.String(),
				},
				Param: &api.Query_Version{Version: pkg.Version},
			}
		}

		resp, err := s.osvClient.QueryBatch(ctx, queries)
		if err != nil {
			return fmt.Errorf("osv query: %w", err)
		}

		s.emitFindings(ctx, pkgs, resp, findings)
	}

	return nil
}

func (s *SCAScanner) emitFindings(
	ctx context.Context,
	pkgs []*extractor.Package,
	resp *api.BatchVulnerabilityList,
	findings chan<- core.Finding,
) {
	for i, vulnList := range resp.GetResults() {
		if i >= len(pkgs) {
			break
		}
		pkg := pkgs[i]
		eco := pkg.Ecosystem()

		for _, vuln := range vulnList.GetVulns() {
			id := vuln.GetId()

			var cve string
			for _, alias := range vuln.GetAliases() {
				if strings.HasPrefix(alias, "CVE-") {
					cve = alias
					break
				}
			}

			var refs []string
			for _, ref := range vuln.GetReferences() {
				refs = append(refs, ref.GetUrl())
			}

			location := ""
			if len(pkg.Locations) > 0 {
				location = pkg.Locations[0]
			}

			finding := core.Finding{
				Type:           core.ScanTypeSCA,
				RuleID:         id,
				RuleName:       id,
				Severity:       core.SeverityMedium,
				Title:          fmt.Sprintf("%s: %s@%s", id, pkg.Name, pkg.Version),
				Description:    vuln.GetSummary(),
				FilePath:       location,
				StartLine:      1,
				EndLine:        1,
				PackageName:    pkg.Name,
				PackageVersion: pkg.Version,
				Ecosystem:      eco.String(),
				FixedVersion:   extractFixedVersion(vuln),
				CVE:            cve,
				References:     refs,
				Tags:           []string{"sca", strings.ToLower(eco.String())},
				Timestamp:      time.Now(),
			}
			finding.ComputeFingerprint()

			select {
			case findings <- finding:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *SCAScanner) Close() error { return nil }

func extractFixedVersion(vuln *osvschema.Vulnerability) string {
	for _, affected := range vuln.GetAffected() {
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				if event.GetFixed() != "" {
					return event.GetFixed()
				}
			}
		}
	}
	return ""
}
