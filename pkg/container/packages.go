package container

import (
	"archive/tar"
	"bufio"
	"io"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type pkg struct {
	Name        string
	Version     string
	LayerDigest string
	LayerIndex  int
	TotalLayers int
}

type distroInfo struct {
	ID      string // alpine, debian, ubuntu, fedora, centos, rhel
	Version string // e.g. "3.19", "12", "22.04"
}

// extractPackages walks layers individually to parse OS packages and attribute each
// package to the layer that introduced it.
func extractPackages(img v1.Image) ([]pkg, distroInfo, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, distroInfo{}, err
	}

	var (
		distro      distroInfo
		prevPkgSet  map[string]bool
		allPkgs     []pkg
	)

	totalLayers := len(layers)
	for layerIdx, layer := range layers {
		layerDigest, _ := layer.Digest()
		digestStr := layerDigest.String()

		apkData, dpkgData, releaseData := extractLayerFiles(layer)

		if releaseData != nil {
			distro = parseOSRelease(releaseData)
		}

		// Parse the full package state from this layer's metadata file.
		var layerPkgs []pkg
		if apkData != nil {
			layerPkgs = parseAPK(apkData)
		}
		if dpkgData != nil {
			layerPkgs = append(layerPkgs, parseDPKG(dpkgData)...)
		}

		if len(layerPkgs) == 0 {
			continue
		}

		// Build current set and diff against previous to find new packages.
		curSet := make(map[string]bool, len(layerPkgs))
		for _, p := range layerPkgs {
			key := p.Name + "@" + p.Version
			curSet[key] = true
			if prevPkgSet == nil || !prevPkgSet[key] {
				allPkgs = append(allPkgs, pkg{
					Name:        p.Name,
					Version:     p.Version,
					LayerDigest: digestStr,
					LayerIndex:  layerIdx,
					TotalLayers: totalLayers,
				})
			}
		}
		prevPkgSet = curSet
	}

	return allPkgs, distro, nil
}

// extractLayerFiles reads a single layer tar for package metadata files.
func extractLayerFiles(layer v1.Layer) (apkData, dpkgData, releaseData []byte) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch name {
		case "lib/apk/db/installed":
			apkData, _ = io.ReadAll(tr)
		case "var/lib/dpkg/status":
			dpkgData, _ = io.ReadAll(tr)
		case "etc/os-release":
			releaseData, _ = io.ReadAll(tr)
		}
	}
	return
}

// parseAPK parses /lib/apk/db/installed (Alpine).
// Format: blocks separated by blank lines, P=name, V=version.
func parseAPK(data []byte) []pkg {
	var pkgs []pkg
	var name, version string

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if name != "" && version != "" {
				pkgs = append(pkgs, pkg{Name: name, Version: version})
			}
			name, version = "", ""
			continue
		}
		if strings.HasPrefix(line, "P:") {
			name = line[2:]
		} else if strings.HasPrefix(line, "V:") {
			version = line[2:]
		}
	}
	if name != "" && version != "" {
		pkgs = append(pkgs, pkg{Name: name, Version: version})
	}
	return pkgs
}

// parseDPKG parses /var/lib/dpkg/status (Debian/Ubuntu).
// Format: blocks separated by blank lines, Package: name, Version: version, Status must contain "installed".
func parseDPKG(data []byte) []pkg {
	var pkgs []pkg
	var name, version, status string

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if name != "" && version != "" && strings.Contains(status, "installed") {
				pkgs = append(pkgs, pkg{Name: name, Version: version})
			}
			name, version, status = "", "", ""
			continue
		}
		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Status: ") {
			status = strings.TrimPrefix(line, "Status: ")
		}
	}
	if name != "" && version != "" && strings.Contains(status, "installed") {
		pkgs = append(pkgs, pkg{Name: name, Version: version})
	}
	return pkgs
}

// parseOSRelease parses /etc/os-release into distro ID and version.
func parseOSRelease(data []byte) distroInfo {
	if data == nil {
		return distroInfo{}
	}
	var d distroInfo
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ID=") {
			d.ID = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			d.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return d
}

// osvEcosystem maps distro ID to the OSV ecosystem string.
func (d distroInfo) osvEcosystem() string {
	switch strings.ToLower(d.ID) {
	case "alpine":
		return "Alpine:v" + majorMinor(d.Version)
	case "debian":
		return "Debian:" + d.Version
	case "ubuntu":
		return "Ubuntu:" + d.Version
	default:
		return ""
	}
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}
