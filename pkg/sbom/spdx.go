package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// SPDX 2.3 JSON format.
type spdxDoc struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      spdxCreation  `json:"creationInfo"`
	Packages          []spdxPackage `json:"packages"`
	Relationships     []spdxRel     `json:"relationships"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string           `json:"SPDXID"`
	Name             string           `json:"name"`
	VersionInfo      string           `json:"versionInfo"`
	DownloadLocation string           `json:"downloadLocation"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRel struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func FormatSPDX(w io.Writer, result *Result) error {
	packages := make([]spdxPackage, len(result.Components))
	relationships := make([]spdxRel, len(result.Components))

	for i, c := range result.Components {
		spdxID := fmt.Sprintf("SPDXRef-Package-%s", spdxSafe(c.Name, c.Version))
		pkg := spdxPackage{
			SPDXID:           spdxID,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
		}
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		packages[i] = pkg
		relationships[i] = spdxRel{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: spdxID,
		}
	}

	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "broly-sbom",
		DocumentNamespace: fmt.Sprintf("https://github.com/Shasheen8/Broly/sbom/%s", uuid()),
		CreationInfo: spdxCreation{
			Created:  result.Timestamp.UTC().Format(time.RFC3339),
			Creators: []string{fmt.Sprintf("Tool: %s-%s", result.Tool, result.Version)},
		},
		Packages:      packages,
		Relationships: relationships,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func spdxSafe(name, version string) string {
	h := sha256.Sum256([]byte(name + "@" + version))
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, name)
	if len(s) > 40 {
		s = s[:40]
	}
	return fmt.Sprintf("%s-%x", s, h[:4])
}
