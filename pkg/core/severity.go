package core

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

func (s *Severity) UnmarshalYAML(value *yaml.Node) error {
	*s = ParseSeverity(value.Value)
	return nil
}

func ParseSeverity(s string) Severity {
	sev, _ := ParseSeverityStrict(s)
	return sev
}

func ParseSeverityStrict(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, true
	case "HIGH":
		return SeverityHigh, true
	case "MEDIUM":
		return SeverityMedium, true
	case "LOW":
		return SeverityLow, true
	case "INFO":
		return SeverityInfo, true
	default:
		return SeverityInfo, false
	}
}

func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
