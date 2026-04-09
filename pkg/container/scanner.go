// Package container scans container images for OS and language package vulnerabilities.
package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/osvutil"
)

type ContainerScanner struct {
	imageRef   string
	quiet      bool
	osvClient  *osvdev.OSVClient
	fixedCache map[string]string
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{}
}

func (s *ContainerScanner) Name() string        { return "container" }
func (s *ContainerScanner) Type() core.ScanType { return core.ScanTypeContainer }

func (s *ContainerScanner) Init(cfg *core.Config) error {
	s.imageRef = cfg.ContainerImage
	s.quiet = cfg.Quiet
	s.osvClient = osvdev.DefaultClient()
	s.osvClient.Config.UserAgent = "broly-container/1.0"
	s.fixedCache = make(map[string]string)
	return nil
}

func (s *ContainerScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)
	if s.imageRef == "" {
		return nil
	}

	img, err := pullImage(ctx, s.imageRef, s.quiet)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", s.imageRef, err)
	}

	digest, _ := img.Digest()
	manifest, _ := img.Manifest()
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}

	var baseImage string
	if manifest != nil && len(manifest.Annotations) > 0 {
		baseImage = manifest.Annotations["org.opencontainers.image.base.name"]
	}

	digestStr := digest.String()
	core.Progressf(s.quiet, "image: %s | digest: %s | layers: %d", s.imageRef, digestStr, len(layers))

	imgMeta := imageMetadata{
		digest:    digestStr,
		baseImage: baseImage,
	}

	pkgs, distro, err := extractPackages(img)
	if err != nil {
		return fmt.Errorf("extract packages: %w", err)
	}

	// OS package scan (requires known distro).
	ecosystem := distro.osvEcosystem()
	if ecosystem != "" && len(pkgs) > 0 {
		core.Progressf(s.quiet, "distro: %s %s | ecosystem: %s | packages: %d", distro.ID, distro.Version, ecosystem, len(pkgs))
		if err := s.scanOSPackages(ctx, pkgs, ecosystem, imgMeta, findings); err != nil {
			return err
		}
	} else if distro.ID != "" {
		core.Warnf("container distro %q is not mapped to an OSV ecosystem", distro.ID)
	}

	// Language package scan (always runs).
	if err := s.scanLanguagePackages(ctx, img, imgMeta, findings); err != nil {
		return fmt.Errorf("container language package scan: %w", err)
	}

	return nil
}

func (s *ContainerScanner) scanOSPackages(ctx context.Context, pkgs []pkg, ecosystem string, imgMeta imageMetadata, findings chan<- core.Finding) error {
	for start := 0; start < len(pkgs); start += 1000 {
		end := start + 1000
		if end > len(pkgs) {
			end = len(pkgs)
		}
		batch := pkgs[start:end]

		queries := make([]*api.Query, len(batch))
		for i, p := range batch {
			queries[i] = &api.Query{
				Package: &osvschema.Package{
					Name:      p.Name,
					Ecosystem: ecosystem,
				},
				Param: &api.Query_Version{Version: p.Version},
			}
		}

		resp, err := s.osvClient.QueryBatch(ctx, queries)
		if err != nil {
			return fmt.Errorf("osv query: %w", err)
		}

		for i, vulnList := range resp.GetResults() {
			if i >= len(batch) {
				break
			}
			p := batch[i]

			for _, vuln := range vulnList.GetVulns() {
				f := s.containerFinding(vuln, p.Name, p.Version, ecosystem, s.imageRef, "", p.LayerDigest, p.LayerIndex, imgMeta)
				select {
				case findings <- f:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
	return nil
}

func (s *ContainerScanner) scanLanguagePackages(ctx context.Context, img v1.Image, meta imageMetadata, findings chan<- core.Finding) error {
	tmpDir, layerResults, err := extractLockfiles(img)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if len(layerResults) == 0 {
		return nil
	}

	// Build scalibr extractors for all supported ecosystems.
	var extractors []filesystem.Extractor
	for _, eco := range []string{"go", "python", "javascript", "ruby", "rust", "java", "php", "dotnet", "dart"} {
		exts, err := list.ExtractorsFromName(eco, &cpb.PluginConfig{})
		if err != nil {
			continue
		}
		extractors = append(extractors, exts...)
	}
	if len(extractors) == 0 {
		return nil
	}

	// Build a map of file path -> layer info for attribution.
	fileToLayer := make(map[string]lockfileResult)
	for _, lr := range layerResults {
		for f := range lr.files {
			fileToLayer[f] = lr
		}
	}

	// Run scalibr on the temp dir.
	var inv inventory.Inventory
	core.WithSuppressedStdlog(func() {
		inv, _, err = filesystem.Run(ctx, &filesystem.Config{
			Extractors: extractors,
			ScanRoots:  []*scalibrfs.ScanRoot{{Path: tmpDir, FS: scalibrfs.DirFS(tmpDir)}},
			Stats:      stats.NoopCollector{},
		})
	})
	if err != nil {
		return err
	}

	pkgs := inv.Packages
	if len(pkgs) == 0 {
		return nil
	}

	core.Progressf(s.quiet, "container language packages: %d", len(pkgs))

	// Query OSV in batches of 1000.
	for start := 0; start < len(pkgs); start += 1000 {
		end := start + 1000
		if end > len(pkgs) {
			end = len(pkgs)
		}
		batch := pkgs[start:end]

		queries := make([]*api.Query, len(batch))
		for i, p := range batch {
			queries[i] = &api.Query{
				Package: &osvschema.Package{
					Name:      p.Name,
					Ecosystem: p.Ecosystem().String(),
				},
				Param: &api.Query_Version{Version: p.Version},
			}
		}

		resp, err := s.osvClient.QueryBatch(ctx, queries)
		if err != nil {
			return fmt.Errorf("osv query (language): %w", err)
		}

		for i, vulnList := range resp.GetResults() {
			if i >= len(batch) {
				break
			}
			p := batch[i]
			eco := p.Ecosystem()
			lr := findLayerForPackage(p.Locations, fileToLayer, tmpDir)
			artifactPath := artifactPathFromLocations(p.Locations, tmpDir)

			for _, vuln := range vulnList.GetVulns() {
				f := s.containerFinding(vuln, p.Name, p.Version, eco.String(), s.imageRef, artifactPath, lr.layerDigest, lr.layerIndex, meta)
				select {
				case findings <- f:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}

	return nil
}

func artifactPathFromLocations(locations []string, tmpDir string) string {
	if len(locations) == 0 {
		return ""
	}
	rel, err := filepath.Rel(tmpDir, locations[0])
	if err != nil {
		return ""
	}
	rel = filepath.Clean(rel)
	if rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

func findLayerForPackage(locations []string, fileToLayer map[string]lockfileResult, tmpDir string) lockfileResult {
	if rel := artifactPathFromLocations(locations, tmpDir); rel != "" {
		if lr, ok := fileToLayer[filepath.FromSlash(rel)]; ok {
			return lr
		}
	}
	return lockfileResult{layerIndex: -1}
}

func (s *ContainerScanner) Close() error { return nil }

type imageMetadata struct {
	digest    string
	baseImage string
}

// containerFinding builds a Finding from a vulnerability match. Used for both OS and language packages.
func (s *ContainerScanner) containerFinding(vuln *osvschema.Vulnerability, pkgName, pkgVersion, ecosystem, imageRef, artifactPath, layerDigest string, layerIndex int, meta imageMetadata) core.Finding {
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

	sev, cvss := containerCVSSSeverity(vuln)
	tags := []string{"container", strings.ToLower(ecosystem)}
	layerNumber := 0
	if layerIndex >= 0 {
		layerNumber = layerIndex + 1
	}

	f := core.Finding{
		Type:           core.ScanTypeContainer,
		RuleID:         id,
		RuleName:       id,
		Severity:       sev,
		CVSSScore:      cvss,
		Title:          fmt.Sprintf("%s: %s@%s", id, pkgName, pkgVersion),
		Description:    vuln.GetSummary(),
		FilePath:       imageRef,
		ArtifactPath:   artifactPath,
		StartLine:      1,
		PackageName:    pkgName,
		PackageVersion: pkgVersion,
		Ecosystem:      ecosystem,
		FixedVersion:   osvutil.ResolveFixedVersion(context.Background(), s.osvClient, vuln, s.fixedCache),
		CVE:            cve,
		References:     refs,
		ImageDigest:    meta.digest,
		LayerDigest:    layerDigest,
		LayerIndex:     layerNumber,
		BaseImage:      meta.baseImage,
		Tags:           tags,
		Timestamp:      time.Now(),
	}
	f.ComputeFingerprint()
	return f
}

func containerCVSSSeverity(vuln *osvschema.Vulnerability) (core.Severity, float64) {
	for _, sev := range vuln.GetSeverity() {
		score := sev.GetScore()
		if f, err := strconv.ParseFloat(score, 64); err == nil {
			return core.SeverityFromCVSS(f), f
		}
		if s, score, ok := core.SeverityFromCVSSVector(score); ok {
			return s, score
		}
	}
	return core.SeverityMedium, 0
}

// pullImage loads a container image from a registry, local Docker daemon, or tarball.
func pullImage(ctx context.Context, ref string, quiet bool) (v1.Image, error) {
	// Tarball: path ends in .tar or .tar.gz
	if strings.HasSuffix(ref, ".tar") || strings.HasSuffix(ref, ".tar.gz") {
		img, err := tarball.ImageFromPath(ref, nil)
		if err != nil {
			return nil, fmt.Errorf("load tarball %s: %w", ref, err)
		}
		return img, nil
	}

	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %s: %w", ref, err)
	}

	img, err := remote.Image(parsed,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err == nil {
		return img, nil
	}
	remoteErr := err

	// Fall back to a local Docker image for unpublished or offline-only refs.
	if dockerAvailable() {
		img, err := daemon.Image(parsed)
		if err == nil {
			core.Progressf(quiet, "using local image after registry pull failed: %v", remoteErr)
			return img, nil
		}
	}
	return nil, fmt.Errorf("pull from registry %s: %w", ref, remoteErr)
}

func dockerAvailable() bool {
	sock := os.Getenv("DOCKER_HOST")
	if sock == "" {
		sock = "/var/run/docker.sock"
	} else if strings.HasPrefix(sock, "unix://") {
		sock = strings.TrimPrefix(sock, "unix://")
	} else {
		return true // tcp or other scheme, let the client try
	}
	_, err := os.Stat(sock)
	return err == nil
}
