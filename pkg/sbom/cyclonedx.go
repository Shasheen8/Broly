package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// CycloneDX 1.5 JSON format.
type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
}

func FormatCycloneDX(w io.Writer, result *Result) error {
	components := make([]cdxComponent, len(result.Components))
	for i, c := range result.Components {
		name, group := splitGroup(c.Name)
		components[i] = cdxComponent{
			Type:    "library",
			Name:    name,
			Version: c.Version,
			PURL:    c.PURL,
			Group:   group,
		}
	}

	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", uuid()),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: result.Timestamp.UTC().Format(time.RFC3339),
			Tools: []cdxTool{{
				Name:    result.Tool,
				Version: result.Version,
			}},
		},
		Components: components,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func splitGroup(name string) (string, string) {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:], name[:idx]
	}
	return name, ""
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
