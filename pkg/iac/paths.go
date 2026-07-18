package iac

import (
	"path/filepath"
	"sort"
	"strings"
)

func isIaCDefinitionPath(p string) bool {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" {
		return false
	}

	ext := strings.ToLower(filepath.Ext(p))
	base := strings.ToLower(filepath.Base(p))
	lowerDir := strings.ToLower(filepath.ToSlash(filepath.Dir(p)))

	switch ext {
	case ".tf":
		return true
	}

	if strings.HasSuffix(base, ".tf.json") {
		return true
	}

	switch base {
	case "chart.yaml", "chart.yml":
		return true
	case "values.yaml", "values.yml":
		return true
	}

	if strings.Contains("/"+lowerDir+"/", "/templates/") {
		if ext == ".yaml" || ext == ".yml" {
			return true
		}
	}

	if ext == ".yaml" || ext == ".yml" {
		if isKubernetesManifestPath(p) || isCloudFormationPath(p) {
			return true
		}
	}

	if ext == ".json" {
		if isCloudFormationPath(p) {
			return true
		}
	}

	return false
}

func isKubernetesManifestPath(p string) bool {
	lower := strings.ToLower(p)
	dir := filepath.ToSlash(filepath.Dir(lower))
	base := strings.ToLower(filepath.Base(p))
	dirSlash := "/" + dir + "/"

	if strings.Contains(dirSlash, "/k8s/") ||
		strings.Contains(dirSlash, "/kubernetes/") ||
		strings.Contains(dirSlash, "/manifests/") ||
		strings.Contains(dirSlash, "/deploy/") ||
		strings.Contains(dirSlash, "/helm/") {
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			return true
		}
	}

	switch base {
	case "deployment.yaml", "deployment.yml",
		"service.yaml", "service.yml",
		"pod.yaml", "pod.yml",
		"daemonset.yaml", "daemonset.yml",
		"statefulset.yaml", "statefulset.yml",
		"job.yaml", "job.yml",
		"cronjob.yaml", "cronjob.yml",
		"configmap.yaml", "configmap.yml",
		"secret.yaml", "secret.yml",
		"ingress.yaml", "ingress.yml",
		"namespace.yaml", "namespace.yml",
		"role.yaml", "role.yml",
		"rolebinding.yaml", "rolebinding.yml",
		"clusterrole.yaml", "clusterrole.yml",
		"clusterrolebinding.yaml", "clusterrolebinding.yml",
		"networkpolicy.yaml", "networkpolicy.yml",
		"pdb.yaml", "pdb.yml",
		"hpa.yaml", "hpa.yml":
		return true
	}

	return false
}

func isCloudFormationPath(p string) bool {
	lower := strings.ToLower(p)
	base := strings.ToLower(filepath.Base(p))

	if strings.Contains(lower, "cloudformation") || strings.Contains(lower, "cfn") {
		return true
	}

	switch base {
	case "template.yaml", "template.yml", "template.json",
		"cloudformation.yaml", "cloudformation.yml", "cloudformation.json",
		"stack.yaml", "stack.yml", "stack.json":
		return true
	}

	return false
}

func TouchesIaCDefinitions(paths []string) bool {
	for _, p := range paths {
		if isIaCDefinitionPath(p) {
			return true
		}
	}
	return false
}

func ChangedIaCScanRoots(paths []string) []string {
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if !isIaCDefinitionPath(p) {
			continue
		}
		p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
		dir := filepath.ToSlash(filepath.Dir(p))
		if dir == "" {
			dir = "."
		}
		filtered = append(filtered, dir)
	}
	return removeNestedDirs(uniqueScanRoots(filtered))
}

func removeNestedDirs(dirs []string) []string {
	if len(dirs) <= 1 {
		return dirs
	}
	sorted := make([]string, len(dirs))
	copy(sorted, dirs)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) < len(sorted[j]) })
	out := make([]string, 0, len(sorted))
	for _, d := range sorted {
		nested := false
		for _, kept := range out {
			if kept == "." || d == kept || strings.HasPrefix(d, kept+"/") {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, d)
		}
	}
	return out
}

func uniqueScanRoots(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
