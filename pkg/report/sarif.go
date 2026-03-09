package report

import (
	"encoding/json"
	"io"

	"github.com/Shasheen8/Broly/pkg/core"
)

const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

type SARIFFormatter struct {
	Version string
}

func (f *SARIFFormatter) Name() string { return "sarif" }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       sarifProperties  `json:"properties,omitempty"`
}

type sarifProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifMessage      `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

func (f *SARIFFormatter) Format(w io.Writer, result *core.ScanResult) error {
	ruleMap := make(map[string]bool)
	var rules []sarifRule
	var results []sarifResult

	for _, finding := range result.Findings {
		if !ruleMap[finding.RuleID] {
			ruleMap[finding.RuleID] = true
			rules = append(rules, sarifRule{
				ID:               finding.RuleID,
				Name:             finding.RuleName,
				ShortDescription: sarifMessage{Text: finding.Title},
				Properties:       sarifProperties{Tags: finding.Tags},
			})
		}

		results = append(results, sarifResult{
			RuleID:  finding.RuleID,
			Level:   severityToSARIFLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: finding.FilePath},
					Region: sarifRegion{
						StartLine:   finding.StartLine,
						EndLine:     finding.EndLine,
						StartColumn: finding.StartColumn,
						EndColumn:   finding.EndColumn,
					},
				},
			}},
			Fingerprints: map[string]string{
				"broly/v1": finding.Fingerprint,
			},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Broly",
					Version:        f.sarifVersion(),
					InformationURI: "https://github.com/Shasheen8/Broly",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	case core.SeverityLow, core.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

func (f *SARIFFormatter) sarifVersion() string {
	if f.Version != "" {
		return f.Version
	}
	return "dev"
}
