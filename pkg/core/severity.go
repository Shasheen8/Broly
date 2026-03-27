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

// SeverityFromCVSSVector parses a CVSS v3 vector string and returns a severity + approximate score.
func SeverityFromCVSSVector(vector string) (Severity, float64, bool) {
	upper := strings.ToUpper(vector)
	if !strings.HasPrefix(upper, "CVSS:") {
		return 0, 0, false
	}
	c := strings.Contains(upper, "/C:H")
	i := strings.Contains(upper, "/I:H")
	a := strings.Contains(upper, "/A:H")
	scopeChanged := strings.Contains(upper, "/S:C")
	network := strings.Contains(upper, "/AV:N")
	lowAC := strings.Contains(upper, "/AC:L")
	noPriv := strings.Contains(upper, "/PR:N") || strings.Contains(upper, "/PR:L")

	twoHigh := (c && i) || (c && a) || (i && a)

	var sev Severity
	var approxScore float64
	switch {
	case twoHigh || (scopeChanged && (c || i || a)):
		sev, approxScore = SeverityCritical, 9.5
	case c || i || a:
		sev, approxScore = SeverityHigh, 8.0
	case network && lowAC && noPriv:
		sev, approxScore = SeverityMedium, 6.5
	default:
		sev, approxScore = SeverityLow, 3.5
	}
	return sev, approxScore, true
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
