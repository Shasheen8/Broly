package routes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpenAPI extraction.
//
// A committed spec is a better route source than any amount of pattern
// matching, for two reasons: it is authoritative rather than inferred, and
// it carries the public path including whatever prefix the gateway serves
// the handler under, which source code usually does not.
//
// It is also the only source for spec-driven frameworks. Connexion, for
// instance, registers every route from the spec at startup, so a repo using
// it has no route literals in its Python at all. Pattern matching finds
// nothing there and would report a clean zero, which reads exactly like a
// service with no endpoints.

// specFileNames are checked before parsing, so the walker does not attempt
// YAML on every config file in the tree.
var specFileHints = []string{
	"openapi", "swagger", "api-spec", "apispec", "api_spec",
}

// maxSpecBytes bounds a spec read. Generated specs get large; a 16 MiB
// ceiling covers real ones without letting a pathological file stall a scan.
const maxSpecBytes = 16 << 20

type openAPIDoc struct {
	OpenAPI string            `yaml:"openapi" json:"openapi"`
	Swagger string            `yaml:"swagger" json:"swagger"`
	BasePath string           `yaml:"basePath" json:"basePath"`
	Servers []openAPIServer   `yaml:"servers" json:"servers"`
	Paths   map[string]pathIt `yaml:"paths" json:"paths"`
}

type openAPIServer struct {
	URL string `yaml:"url" json:"url"`
}

type pathIt map[string]operation

type operation struct {
	OperationID string           `yaml:"operationId" json:"operationId"`
	Summary     string           `yaml:"summary" json:"summary"`
	Parameters  []openAPIParam   `yaml:"parameters" json:"parameters"`
	Security    []map[string]any `yaml:"security" json:"security"`
}

type openAPIParam struct {
	Name string `yaml:"name" json:"name"`
	In   string `yaml:"in" json:"in"`
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true, "trace": true,
}

// specRoutes finds every OpenAPI or Swagger document under root and returns
// the routes they declare.
func specRoutes(root string, files []string) []Route {
	var out []Route
	for _, path := range files {
		if !looksLikeSpecFile(path) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxSpecBytes {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		doc, ok := parseSpec(path, data)
		if !ok {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		out = append(out, routesFromSpec(doc, rel)...)
	}
	return out
}

func looksLikeSpecFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml", ".json":
	default:
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	for _, hint := range specFileHints {
		if strings.Contains(base, hint) {
			return true
		}
	}
	// A directory named openapi_specs/ or api/spec/ is as good a hint as
	// the filename: connexion projects commonly use openapi3.yml.
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(path)))
	return strings.Contains(dir, "openapi") || strings.Contains(dir, "swagger") ||
		strings.Contains(dir, "api_specs") || strings.Contains(dir, "api-specs")
}

func parseSpec(path string, data []byte) (*openAPIDoc, bool) {
	var doc openAPIDoc
	if strings.EqualFold(filepath.Ext(path), ".json") {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, false
		}
	} else if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	// Require a version marker and at least one path. Without both this is
	// some other YAML file that happens to live in a directory we liked.
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return nil, false
	}
	if len(doc.Paths) == 0 {
		return nil, false
	}
	return &doc, true
}

func routesFromSpec(doc *openAPIDoc, relPath string) []Route {
	prefix := specPrefix(doc)

	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []Route
	for _, p := range paths {
		methods := make([]string, 0, len(doc.Paths[p]))
		for m := range doc.Paths[p] {
			if httpMethods[strings.ToLower(m)] {
				methods = append(methods, m)
			}
		}
		sort.Strings(methods)

		for _, m := range methods {
			op := doc.Paths[p][m]
			full := normalizePath(prefix + p)
			out = append(out, Route{
				Method:       strings.ToUpper(m),
				PathTemplate: full,
				Params:       specParams(p, op),
				HandlerFile:  relPath,
				HandlerLine:  1,
				Framework:    "openapi",
				AuthGuard:    specAuthGuard(op),
			})
		}
	}
	return out
}

// specPrefix recovers the path prefix the service is actually served under:
// Swagger 2 states it directly, OpenAPI 3 buries it in the server URL. This
// is the part source code does not know and a scanner most needs.
func specPrefix(doc *openAPIDoc) string {
	if doc.BasePath != "" && doc.BasePath != "/" {
		return strings.TrimSuffix(doc.BasePath, "/")
	}
	for _, s := range doc.Servers {
		u := s.URL
		if u == "" || strings.Contains(u, "{") {
			continue // templated server variable; not resolvable here
		}
		if i := strings.Index(u, "://"); i >= 0 {
			u = u[i+3:]
			if j := strings.Index(u, "/"); j >= 0 {
				u = u[j:]
			} else {
				u = ""
			}
		}
		if u != "" && u != "/" {
			return strings.TrimSuffix(u, "/")
		}
	}
	return ""
}

func specParams(path string, op operation) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range pathParams(path) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, p := range op.Parameters {
		if p.Name == "" || p.In == "header" {
			continue
		}
		if _, ok := seen[p.Name]; !ok {
			seen[p.Name] = struct{}{}
			out = append(out, p.Name)
		}
	}
	return out
}

// specAuthGuard reports what the operation declares. An explicit empty
// security array means "this endpoint opts out of auth", which is worth
// distinguishing from "the spec says nothing".
func specAuthGuard(op operation) string {
	if op.Security == nil {
		return ""
	}
	if len(op.Security) == 0 {
		return "none"
	}
	for _, entry := range op.Security {
		for name := range entry {
			lower := strings.ToLower(name)
			switch {
			case strings.Contains(lower, "bearer"), strings.Contains(lower, "jwt"),
				strings.Contains(lower, "oauth"), strings.Contains(lower, "token"):
				return "bearer"
			case strings.Contains(lower, "apikey"), strings.Contains(lower, "api_key"):
				return "bearer"
			case strings.Contains(lower, "cookie"), strings.Contains(lower, "session"):
				return "session"
			}
		}
	}
	return "bearer"
}
