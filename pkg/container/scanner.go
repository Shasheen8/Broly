// Package container scans container images for OS and language package vulnerabilities.
package container

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"

	"github.com/Shasheen8/Broly/pkg/core"
)

type ContainerScanner struct {
	imageRef  string
	osvClient *osvdev.OSVClient
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{}
}

func (s *ContainerScanner) Name() string        { return "container" }
func (s *ContainerScanner) Type() core.ScanType { return core.ScanTypeContainer }

func (s *ContainerScanner) Init(cfg *core.Config) error {
	s.imageRef = cfg.ContainerImage
	s.osvClient = osvdev.DefaultClient()
	s.osvClient.Config.UserAgent = "broly-container/1.0"
	return nil
}

func (s *ContainerScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)
	if s.imageRef == "" {
		return nil
	}

	img, err := pullImage(ctx, s.imageRef)
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
	fmt.Fprintf(os.Stderr, "image: %s | digest: %s | layers: %d\n", s.imageRef, digestStr, len(layers))

	pkgs, distro, err := extractPackages(img)
	if err != nil {
		return fmt.Errorf("extract packages: %w", err)
	}

	ecosystem := distro.osvEcosystem()
	if ecosystem == "" {
		fmt.Fprintf(os.Stderr, "warning: unknown distro %q — skipping vuln matching\n", distro.ID)
		return nil
	}

	imgMeta := imageMetadata{
		digest:    digestStr,
		baseImage: baseImage,
	}

	fmt.Fprintf(os.Stderr, "distro: %s %s | ecosystem: %s | packages: %d\n", distro.ID, distro.Version, ecosystem, len(pkgs))

	if len(pkgs) == 0 {
		return nil
	}

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
				f := vulnToFinding(vuln, p, ecosystem, s.imageRef, imgMeta)
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

func (s *ContainerScanner) Close() error { return nil }

type imageMetadata struct {
	digest    string
	baseImage string
}

func vulnToFinding(vuln *osvschema.Vulnerability, p pkg, ecosystem, imageRef string, meta imageMetadata) core.Finding {
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
	f := core.Finding{
		Type:           core.ScanTypeContainer,
		RuleID:         id,
		RuleName:       id,
		Severity:       sev,
		CVSSScore:      cvss,
		Title:          fmt.Sprintf("%s: %s@%s", id, p.Name, p.Version),
		Description:    vuln.GetSummary(),
		FilePath:       imageRef,
		StartLine:      1,
		PackageName:    p.Name,
		PackageVersion: p.Version,
		Ecosystem:      ecosystem,
		FixedVersion:   containerFixedVersion(vuln),
		CVE:            cve,
		References:     refs,
		ImageDigest:    meta.digest,
		LayerDigest:    p.LayerDigest,
		BaseImage:      meta.baseImage,
		Tags:           containerTags(p, ecosystem),
		Timestamp:      time.Now(),
	}
	f.ComputeFingerprint()
	return f
}

func containerTags(p pkg, ecosystem string) []string {
	tags := []string{"container", strings.ToLower(ecosystem)}
	if p.LayerIndex == 0 {
		tags = append(tags, "base-layer")
	} else {
		tags = append(tags, "app-layer")
	}
	return tags
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

func containerFixedVersion(vuln *osvschema.Vulnerability) string {
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

// pullImage loads a container image from a registry, local Docker daemon, or tarball.
func pullImage(ctx context.Context, ref string) (v1.Image, error) {
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

	// Try local Docker daemon if the socket exists.
	if dockerAvailable() {
		img, err := daemon.Image(parsed)
		if err == nil {
			return img, nil
		}
	}

	// Fall back to remote registry.
	img, err := remote.Image(parsed,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("pull from registry %s: %w", ref, err)
	}
	return img, nil
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
