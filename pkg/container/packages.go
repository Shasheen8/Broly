package container

import (
	"archive/tar"
	"bufio"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	_ "modernc.org/sqlite"
)

// lockfileNames are filenames that osv-scalibr can extract packages from.
var lockfileNames = map[string]bool{
	"requirements.txt": true, "requirements-dev.txt": true,
	"Pipfile.lock": true, "poetry.lock": true, "pdm.lock": true,
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.sum": true, "go.mod": true,
	"Gemfile.lock": true,
	"Cargo.lock": true,
	"composer.lock": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	"packages.lock.json": true, "packages.config": true,
	"pubspec.lock": true,
	"mix.lock": true,
	"rebar.lock": true,
}

// lockfileResult tracks an extracted lockfile and the layer it came from.
type lockfileResult struct {
	layerDigest string
	layerIndex  int
	files       map[string]bool // relative paths written to tempdir
}

const maxLockfileSize = 10 * 1024 * 1024 // 10MB cap per lockfile

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

		apkData, dpkgData, rpmData, releaseData := extractLayerFiles(layer)

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
		if rpmData != nil {
			layerPkgs = append(layerPkgs, parseRPM(rpmData)...)
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
func extractLayerFiles(layer v1.Layer) (apkData, dpkgData, rpmData, releaseData []byte) {
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
		case "var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite":
			rpmData, _ = io.ReadAll(tr)
		case "etc/os-release", "usr/lib/os-release":
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

// parseRPM parses an rpmdb.sqlite file (RHEL 8+, Fedora 33+).
func parseRPM(data []byte) []pkg {
	tmp, err := os.CreateTemp("", "broly-rpmdb-*.sqlite")
	if err != nil {
		return nil
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := tmp.Write(data); err != nil {
		return nil
	}
	tmp.Close()

	db, err := sql.Open("sqlite", tmp.Name())
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, version, release FROM Packages")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var pkgs []pkg
	for rows.Next() {
		var name, version, release string
		if err := rows.Scan(&name, &version, &release); err != nil {
			continue
		}
		ver := version
		if release != "" {
			ver += "-" + release
		}
		pkgs = append(pkgs, pkg{Name: name, Version: ver})
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
	case "rhel", "centos", "rocky", "almalinux", "ol":
		return "Red Hat:" + majorOnly(d.Version)
	case "fedora":
		return "Fedora:" + d.Version
	default:
		return ""
	}
}

// extractLockfiles walks image layers and writes any lockfiles to a temp directory.
// Returns the temp dir path (caller must clean up) and per-file layer attribution.
func extractLockfiles(img v1.Image) (string, []lockfileResult, error) {
	layers, err := img.Layers()
	if err != nil {
		return "", nil, err
	}

	tmpDir, err := os.MkdirTemp("", "broly-container-sca-*")
	if err != nil {
		return "", nil, err
	}

	var results []lockfileResult

	for layerIdx, layer := range layers {
		layerDigest, _ := layer.Digest()

		rc, err := layer.Uncompressed()
		if err != nil {
			continue
		}

		lr := lockfileResult{
			layerDigest: layerDigest.String(),
			layerIndex:  layerIdx,
			files:       make(map[string]bool),
		}

		tr := tar.NewReader(rc)
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			if hdr.Typeflag != tar.TypeReg {
				continue
			}

			name := strings.TrimPrefix(hdr.Name, "./")
			base := filepath.Base(name)
			if !lockfileNames[base] {
				continue
			}

			if hdr.Size > maxLockfileSize {
				continue
			}

			destPath := filepath.Join(tmpDir, name)
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				continue
			}
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				continue
			}
			io.Copy(f, io.LimitReader(tr, maxLockfileSize))
			f.Close()
			lr.files[name] = true
		}
		rc.Close()

		if len(lr.files) > 0 {
			results = append(results, lr)
		}
	}

	return tmpDir, results, nil
}

func majorOnly(v string) string {
	if idx := strings.Index(v, "."); idx >= 0 {
		return v[:idx]
	}
	return v
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}
