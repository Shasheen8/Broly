package sast

import "github.com/Shasheen8/Broly/pkg/core"

func EnrichFindings(findings []core.Finding) {
	for i := range findings {
		if enrichFindingLines(&findings[i]) {
			findings[i].ComputeIdentityKeys()
		}
	}
}

func enrichFindingLines(f *core.Finding) bool {
	if f == nil || f.StartLine > 0 {
		return false
	}
	switch f.Type {
	case core.ScanTypeSAST, core.ScanTypeDockerfile:
	default:
		return false
	}
	for _, text := range []string{f.Description, f.Title, f.FixSuggestion} {
		if line := extractLineNumber(text); line > 0 {
			f.StartLine = line
			return true
		}
	}
	return false
}
