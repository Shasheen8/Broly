package osvutil

import (
	"context"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type VulnGetter interface {
	GetVulnByID(context.Context, string) (*osvschema.Vulnerability, error)
}

func ExtractFixedVersion(vuln *osvschema.Vulnerability) string {
	if vuln == nil {
		return ""
	}
	for _, affected := range vuln.GetAffected() {
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				if event.GetFixed() != "" {
					return event.GetFixed()
				}
			}
		}
	}
	return ""
}

func ResolveFixedVersion(ctx context.Context, getter VulnGetter, vuln *osvschema.Vulnerability, cache map[string]string) string {
	fixed := ExtractFixedVersion(vuln)
	if fixed != "" || vuln == nil {
		return fixed
	}

	id := vuln.GetId()
	if id == "" || getter == nil {
		return ""
	}
	if cache != nil {
		if cached, ok := cache[id]; ok {
			return cached
		}
	}

	full, err := getter.GetVulnByID(ctx, id)
	if err == nil {
		fixed = ExtractFixedVersion(full)
	}
	if cache != nil {
		cache[id] = fixed
	}
	return fixed
}
