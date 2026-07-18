package workflow

import "strings"

func remediation(ident, docURL string) (suggestion string) {
	switch strings.TrimSpace(ident) {
	case "unpinned-uses":
		suggestion = "Pin the action to a full commit SHA instead of a branch or floating tag (for example `actions/checkout@<40-char-sha>`)."
	case "artipacked":
		suggestion = "Remove unnecessary `actions/upload-artifact` or `actions/download-artifact` steps, or scope artifacts to what the workflow actually needs."
	case "cache-poisoning":
		suggestion = "Restrict cache keys to trusted refs and avoid restoring caches from fork PRs or untrusted branches."
	case "excessive-permissions":
		suggestion = "Set the narrowest `permissions:` block for the job or workflow instead of relying on the default GITHUB_TOKEN scope."
	case "secrets-in-log-output":
		suggestion = "Stop echoing secret values in logs; pass secrets only through `env:` or masked inputs."
	case "insecure-command":
		suggestion = "Avoid running untrusted input in shell steps; use environment variables and quoted arguments instead of string interpolation."
	case "template-injection":
		suggestion = "Do not pass untrusted PR or issue fields directly into `run:` scripts; assign them to env vars and reference the env var."
	default:
		suggestion = "Review this GitHub Actions finding and apply the remediation described in the zizmor audit docs."
	}
	if docURL != "" {
		suggestion += " Docs: " + docURL
	}
	return suggestion
}
