package sca

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	registryModeAuto       = "auto"
	registryModePublicOnly = "public-only"
	registryModeCustomOnly = "custom-only"
)

func buildRegistryBackends(cfg *core.Config) ([]registryBackend, error) {
	mode := strings.TrimSpace(strings.ToLower(cfg.PackageRegistryMode))
	if mode == "" {
		mode = registryModeAuto
	}

	switch mode {
	case registryModeAuto, registryModePublicOnly, registryModeCustomOnly:
	default:
		return nil, fmt.Errorf("unknown package registry mode %q", cfg.PackageRegistryMode)
	}

	custom, err := customRegistryBackends(cfg)
	if err != nil {
		return nil, err
	}

	backends := make([]registryBackend, 0, len(custom)+3)
	if mode == registryModeAuto || mode == registryModeCustomOnly {
		backends = append(backends, custom...)
	}
	if mode == registryModeAuto || mode == registryModePublicOnly {
		backends = append(backends, publicRegistryBackends()...)
	}

	return backends, nil
}

func publicRegistryBackends() []registryBackend {
	return []registryBackend{
		newHTTPRegistryBackend("npm-public", "npm", "https://registry.npmjs.org"),
		newHTTPRegistryBackend("pypi-public", "pypi", "https://pypi.org"),
		newHTTPRegistryBackend("crates-public", "crates", "https://crates.io"),
	}
}

func customRegistryBackends(cfg *core.Config) ([]registryBackend, error) {
	custom := make([]registryBackend, 0, 3)

	if cfg.NPMRegistryURL != "" {
		baseURL, err := normalizeRegistryBaseURL(cfg.NPMRegistryURL)
		if err != nil {
			return nil, fmt.Errorf("invalid npm registry url: %w", err)
		}
		custom = append(custom, newHTTPRegistryBackend("npm-custom", "npm", baseURL))
	}
	if cfg.PyPIRegistryURL != "" {
		baseURL, err := normalizeRegistryBaseURL(cfg.PyPIRegistryURL)
		if err != nil {
			return nil, fmt.Errorf("invalid pypi registry url: %w", err)
		}
		custom = append(custom, newHTTPRegistryBackend("pypi-custom", "pypi", baseURL))
	}
	if cfg.CratesRegistryURL != "" {
		baseURL, err := normalizeRegistryBaseURL(cfg.CratesRegistryURL)
		if err != nil {
			return nil, fmt.Errorf("invalid crates registry url: %w", err)
		}
		custom = append(custom, newHTTPRegistryBackend("crates-custom", "crates", baseURL))
	}

	return custom, nil
}

func normalizeRegistryBaseURL(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("registry url must include scheme and host")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
