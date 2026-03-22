package container

import (
	"archive/tar"
	"bufio"
	"io"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

type pkg struct {
	Name    string
	Version string
}

type distroInfo struct {
	ID      string // alpine, debian, ubuntu, fedora, centos, rhel
	Version string // e.g. "3.19", "12", "22.04"
}

// extractPackages reads the flattened image filesystem and parses OS package metadata.
func extractPackages(img v1.Image) ([]pkg, distroInfo, error) {
	reader := mutate.Extract(img)
	defer reader.Close()

	var (
		apkData     []byte
		dpkgData    []byte
		releaseData []byte
	)

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
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

		if apkData != nil && dpkgData != nil && releaseData != nil {
			break
		}
	}

	distro := parseOSRelease(releaseData)

	var pkgs []pkg
	if apkData != nil {
		pkgs = append(pkgs, parseAPK(apkData)...)
	}
	if dpkgData != nil {
		pkgs = append(pkgs, parseDPKG(dpkgData)...)
	}
	return pkgs, distro, nil
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
