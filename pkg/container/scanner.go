// Package container scans container images for OS and language package vulnerabilities.
package container

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Shasheen8/Broly/pkg/core"
)

type ContainerScanner struct {
	imageRef string
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{}
}

func (s *ContainerScanner) Name() string        { return "container" }
func (s *ContainerScanner) Type() core.ScanType { return core.ScanTypeContainer }

func (s *ContainerScanner) Init(cfg *core.Config) error {
	s.imageRef = cfg.ContainerImage
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

	var baseImage string
	if manifest != nil && len(manifest.Annotations) > 0 {
		baseImage = manifest.Annotations["org.opencontainers.image.base.name"]
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}

	fmt.Fprintf(os.Stderr, "image: %s | digest: %s | layers: %d\n", s.imageRef, digest, len(layers))
	if baseImage != "" {
		fmt.Fprintf(os.Stderr, "base image: %s\n", baseImage)
	}

	// TODO: Phase 6B item 4 — extract packages from layers via Syft catalogers
	// TODO: Phase 6B item 5 — feed packages through OSV pipeline for vuln matching

	return nil
}

func (s *ContainerScanner) Close() error { return nil }

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
