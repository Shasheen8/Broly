package triage

import "github.com/Shasheen8/Broly/pkg/core"

// Eligible is true for scan types that get hosted Together AI triage (verdict + fix text).
// Secrets and container base-image advisories are scanner-only on the hosted path.
func Eligible(f core.Finding) bool {
	switch f.Type {
	case core.ScanTypeSAST, core.ScanTypeSCA, core.ScanTypeWorkflow:
		return true
	default:
		return false
	}
}
