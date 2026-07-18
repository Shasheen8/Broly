package triage

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Shasheen8/Broly/pkg/core"
)

const maxFPReasonRunes = 500

type OrgFPReasonLookup func(orgMatchKey string) []string

func SanitizeFPReasonText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxFPReasonRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxFPReasonRunes]) + "..."
}

func appendOrgFPReasonContext(sb *strings.Builder, reasons []string) {
	if len(reasons) == 0 {
		return
	}
	limit := len(reasons)
	if limit > 3 {
		limit = 3
	}
	var bullets strings.Builder
	for _, reason := range reasons[:limit] {
		reason = SanitizeFPReasonText(reason)
		if reason == "" {
			continue
		}
		fmt.Fprintf(&bullets, "- %s\n", reason)
	}
	if bullets.Len() == 0 {
		return
	}
	sb.WriteString("\nPrior org false-positive reasoning for similar findings:\n")
	sb.WriteString(bullets.String())
}

func orgMatchKeyForFinding(f *core.Finding) string {
	if f == nil {
		return ""
	}
	if key := strings.TrimSpace(f.OrgMatchKey); key != "" {
		return key
	}
	tmp := *f
	tmp.ComputeOrgMatchKey()
	return tmp.OrgMatchKey
}

func orgFPReasonsForFinding(f *core.Finding, lookup OrgFPReasonLookup) []string {
	if lookup == nil {
		return nil
	}
	key := orgMatchKeyForFinding(f)
	if key == "" {
		return nil
	}
	return lookup(key)
}

func MergeOrgFPReasons(groups ...[]string) []string {
	seen := make(map[string]bool, 8)
	out := make([]string, 0, 3)
	for _, group := range groups {
		for _, reason := range group {
			reason = SanitizeFPReasonText(reason)
			if reason == "" || seen[reason] {
				continue
			}
			seen[reason] = true
			out = append(out, reason)
			if len(out) == 3 {
				return out
			}
		}
	}
	return out
}

func finalizeFalsePositiveReason(verdict, reason string) string {
	reason = SanitizeFPReasonText(reason)
	if verdict != "FALSE_POSITIVE" {
		return reason
	}
	if reason != "" {
		return reason
	}
	return "Marked false positive without a specific model reason."
}

func mergeParsedReason(reason, fpReason string) string {
	reason = SanitizeFPReasonText(reason)
	fpReason = SanitizeFPReasonText(fpReason)
	if reason != "" {
		return reason
	}
	return fpReason
}
