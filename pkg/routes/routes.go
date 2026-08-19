// Package routes extracts the HTTP routes a repository declares, and the
// dangerous sinks reachable from each handler.
//
// This is deliberately not a vulnerability scanner. It answers a different
// question than the SAST engine does: not "is this code wrong" but "what
// surface does this code expose, and where does each entry point lead".
//
// The consumer is a black-box scanner. Given a route inventory it can seed
// its request corpus with endpoints no crawler would guess (unlinked admin
// handlers, feature-flagged paths, internal-only routes), turn its coverage
// denominator from "endpoints we found by guessing" into "endpoints that
// exist", and prioritise probes at handlers whose sinks match the bug class
// being tested.
//
// Extraction is pattern-based rather than AST-based. That is a real limit
// and worth stating: a route assembled at runtime from a variable, or
// registered through a framework wrapper we do not recognise, will be
// missed. The output is therefore a floor on the declared surface, never a
// complete enumeration, and every consumer is expected to treat an absent
// route as unknown rather than as absent.
package routes

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Shasheen8/Broly/pkg/scanignore"
)

// Sink is a dangerous operation reachable from a handler.
type Sink struct {
	// Kind is the vulnerability class, using the same vocabulary as the
	// SAST vuln-class flags: sqli, xss, rce, ssrf, xxe, idor, bola,
	// path_traversal, deserialization, open_redirect.
	Kind string `json:"kind"`
	CWE  string `json:"cwe,omitempty"`
	File string `json:"file"`
	Line int    `json:"line"`
	// Snippet is the matched source line, trimmed. Useful for a human
	// deciding whether the match is real.
	Snippet string `json:"snippet,omitempty"`
}

// Route is one declared HTTP entry point.
type Route struct {
	Method       string   `json:"method"`
	PathTemplate string   `json:"path_template"`
	Params       []string `json:"params,omitempty"`
	HandlerFile  string   `json:"handler_file"`
	HandlerLine  int      `json:"handler_line"`
	// AuthGuard names the authentication the route appears to require
	// ("bearer", "session", "none", or "" when undetermined). Advisory:
	// a black-box scanner should confirm it, not trust it.
	AuthGuard string `json:"auth_guard,omitempty"`
	Framework string `json:"framework,omitempty"`
	Sinks     []Sink `json:"sinks,omitempty"`
}

// Inventory is the full extraction result.
type Inventory struct {
	Root   string  `json:"root"`
	Routes []Route `json:"routes"`
	// FilesScanned and Skipped make the floor explicit: a consumer can see
	// how much of the tree was actually read.
	FilesScanned int `json:"files_scanned"`
	// Warnings records what the extractor knows it could not do, so a
	// thin inventory is distinguishable from a small codebase.
	Warnings []string `json:"warnings,omitempty"`
}

// maxFileBytes skips generated bundles and vendored blobs, which produce
// noise rather than routes.
const maxFileBytes = 2 << 20

// Extract walks root and returns every route it can identify.
func Extract(root string) (*Inventory, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{Root: abs}

	var files []string
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, do not abort the scan
		}
		if d.IsDir() {
			if scanignore.IsIgnoredDirName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if scanignore.IsTestFile(path) {
			return nil
		}
		_, isSource := supportedExt(path)
		if !isSource && !looksLikeSpecFile(path) {
			return nil
		}
		if info, statErr := d.Info(); statErr == nil && info.Size() > maxFileBytes {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var all []Route
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		inv.FilesScanned++
		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			rel = path
		}
		lang, isSource := supportedExt(path)
		if !isSource {
			continue // spec file; handled by specRoutes below
		}
		src := string(data)

		found := extractRoutes(lang, rel, src)
		sinks := extractSinks(lang, rel, src)
		// Sinks are attributed per file rather than per handler: without an
		// AST we cannot prove a call graph, and claiming we can would make
		// the inventory look more precise than it is. File-level is enough
		// for prioritisation, which is all a consumer should use it for.
		for i := range found {
			found[i].Sinks = sinks
		}
		all = append(all, found...)
	}

	all = append(all, nextJSFileRoutes(abs, files)...)
	// A committed spec outranks pattern matching: it is authoritative, it
	// carries the served prefix, and for spec-driven frameworks like
	// connexion it is the only place routes exist at all.
	all = append(all, specRoutes(abs, files)...)
	inv.Routes = dedupeRoutes(all)

	if len(inv.Routes) == 0 && inv.FilesScanned > 0 {
		inv.Warnings = append(inv.Warnings,
			"no routes matched; the repository may use a framework this extractor does not recognise")
	}
	inv.Warnings = append(inv.Warnings,
		"routes are matched by pattern, not by parsing: dynamically registered or wrapper-registered routes are missed, so this is a floor on the declared surface")
	return inv, nil
}

func supportedExt(path string) (string, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go", true
	case ".py":
		return "python", true
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return "javascript", true
	case ".rb":
		return "ruby", true
	case ".java":
		return "java", true
	}
	return "", false
}

// routePattern is one framework's way of declaring a route.
type routePattern struct {
	framework string
	re        *regexp.Regexp
	// methodFrom names where the HTTP method comes from: a capture group
	// index, or 0 when the pattern implies "any".
	methodGroup int
	pathGroup   int
	// fixedMethod is used when the pattern itself names the method.
	fixedMethod string
	// allowRelative permits a path with no leading slash. Only frameworks
	// that genuinely register relative paths set this. Everywhere else a
	// rooted path is required, because `.Get("X-API-Key")` reading a header
	// is indistinguishable from `.Get("/users")` registering a route until
	// you insist the route be rooted.
	allowRelative bool
}

var routePatterns = map[string][]routePattern{
	"go": {
		// chi / gin / echo / fiber: r.Get("/path", h), app.POST("/path", h)
		{framework: "go-router", re: regexp.MustCompile(`(?i)\.\s*(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["` + "`" + `]([^"` + "`" + `]+)["` + "`" + `]`), methodGroup: 1, pathGroup: 2},
		// gorilla/mux + net/http: HandleFunc("/path", h)
		{framework: "net-http", re: regexp.MustCompile(`(?i)\.?\s*Handle(?:Func)?\s*\(\s*["` + "`" + `]([^"` + "`" + `]+)["` + "`" + `]`), pathGroup: 1},
		// go1.22 ServeMux: mux.HandleFunc("GET /path", h)
		{framework: "servemux", re: regexp.MustCompile(`Handle(?:Func)?\s*\(\s*"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^"]+)"`), methodGroup: 1, pathGroup: 2},
	},
	"python": {
		// FastAPI: @app.get("/path"), @router.post("/path")
		{framework: "fastapi", re: regexp.MustCompile(`(?i)@\s*\w+\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']`), methodGroup: 1, pathGroup: 2},
		// Flask: @app.route("/path", methods=["POST"])
		{framework: "flask", re: regexp.MustCompile(`@\s*\w+\s*\.\s*route\s*\(\s*["']([^"']+)["']`), pathGroup: 1},
		// Django: path("route/", view), re_path(r"^route$", view)
		{framework: "django", allowRelative: true, re: regexp.MustCompile(`(?:^|\s)(?:re_)?path\s*\(\s*r?["']([^"']+)["']`), pathGroup: 1},
	},
	"javascript": {
		// Express / Koa / Fastify: app.get('/path', h), router.post("/path", h)
		{framework: "express", re: regexp.MustCompile(`(?i)\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`), methodGroup: 1, pathGroup: 2},
		// NestJS decorators: @Get('path')
		{framework: "nestjs", allowRelative: true, re: regexp.MustCompile(`@\s*(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["'` + "`" + `]?([^"'` + "`" + `)]*)["'` + "`" + `]?\s*\)`), methodGroup: 1, pathGroup: 2},
	},
	"ruby": {
		// Rails routes.rb: get "/path" => "controller#action"
		{framework: "rails", allowRelative: true, re: regexp.MustCompile(`(?i)^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']`), methodGroup: 1, pathGroup: 2},
	},
	"java": {
		// Spring: @GetMapping("/path"), @RequestMapping(value = "/path")
		{framework: "spring", allowRelative: true, re: regexp.MustCompile(`@\s*(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`), methodGroup: 1, pathGroup: 2},
		{framework: "spring", allowRelative: true, re: regexp.MustCompile(`@\s*RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`), pathGroup: 1},
	},
}

// pathParamRe matches the three common path-parameter spellings:
// :id, {id}, and <int:id>.
var pathParamRe = regexp.MustCompile(`:(\w+)|\{(\w+)(?::[^}]*)?\}|<(?:\w+:)?(\w+)>`)

func extractRoutes(lang, relPath, src string) []Route {
	patterns := routePatterns[lang]
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(src, "\n")
	var out []Route

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isComment(lang, trimmed) {
			continue
		}
		for _, p := range patterns {
			m := p.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			path := m[p.pathGroup]
			if !looksLikeRoutePath(path, p.allowRelative) {
				continue
			}
			method := p.fixedMethod
			if p.methodGroup > 0 && p.methodGroup < len(m) {
				method = strings.ToUpper(m[p.methodGroup])
			}
			if method == "" || method == "ALL" {
				method = "ANY"
			}
			out = append(out, Route{
				Method:       method,
				PathTemplate: normalizePath(path),
				Params:       pathParams(path),
				HandlerFile:  relPath,
				HandlerLine:  i + 1,
				Framework:    p.framework,
				AuthGuard:    guessAuthGuard(lines, i),
			})
			break // one route per line; the first matching pattern wins
		}
	}
	return out
}

func isComment(lang, trimmed string) bool {
	switch lang {
	case "python", "ruby":
		return strings.HasPrefix(trimmed, "#")
	default:
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*")
	}
}

// looksLikeRoutePath rejects the many string literals that are not routes:
// header names, format strings, globs, file paths, and empty matches.
func looksLikeRoutePath(p string, allowRelative bool) bool {
	if p == "" || len(p) > 200 {
		return false
	}
	if strings.ContainsAny(p, " \t\n%") {
		return false
	}
	if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "^") {
		return true
	}
	if !allowRelative {
		return false
	}
	// Relative segment, e.g. NestJS @Get('profile') or a Rails route. Reject
	// anything header-shaped so a Title-Case-Hyphenated literal cannot pass.
	if headerLikeRe.MatchString(p) {
		return false
	}
	return relativeRouteRe.MatchString(p)
}

var (
	// headerLikeRe matches Title-Case-Hyphenated tokens: X-API-Key,
	// Content-Type, Authorization.
	headerLikeRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$`)
	// relativeRouteRe matches a bare path segment or parameter.
	relativeRouteRe = regexp.MustCompile(`^[\w:{<][\w:{}<>./-]*$`)
)

func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "^")
	p = strings.TrimSuffix(p, "$")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func pathParams(p string) []string {
	var out []string
	for _, m := range pathParamRe.FindAllStringSubmatch(p, -1) {
		for _, g := range m[1:] {
			if g != "" {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// authHints are looked for in the few lines above a route declaration,
// where middleware and decorators live.
var authHints = []struct {
	guard string
	words []string
}{
	{"bearer", []string{"bearer", "jwt", "oauth", "api_key", "apikey", "token_required", "authorizationheader"}},
	{"session", []string{"login_required", "session", "cookie", "authenticate_user", "ensureloggedin"}},
	{"none", []string{"allow_any", "permit_all", "public", "anonymous", "skipauth"}},
}

// guessAuthGuard is a heuristic over the surrounding lines and is reported
// as advisory. A scanner should confirm it against the live target rather
// than skipping a route because the source looked guarded.
func guessAuthGuard(lines []string, idx int) string {
	start := idx - 4
	if start < 0 {
		start = 0
	}
	window := strings.ToLower(strings.Join(lines[start:idx+1], "\n"))
	for _, h := range authHints {
		for _, w := range h.words {
			if strings.Contains(window, w) {
				return h.guard
			}
		}
	}
	return ""
}

// sinkPattern maps a dangerous call to the bug class a scanner should
// prioritise at any route in the same file.
type sinkPattern struct {
	kind string
	cwe  string
	re   *regexp.Regexp
}

var sinkPatterns = []sinkPattern{
	{"sqli", "CWE-89", regexp.MustCompile(`(?i)(db|conn|session|cursor|client)\s*\.\s*(Query|Exec|Raw|execute|executemany)\s*\(|\bSELECT\s+.*\bFROM\b.*(\+|%s|\$\{|f")`)},
	{"rce", "CWE-78", regexp.MustCompile(`(?i)\b(exec\.Command|os/exec|subprocess\.(run|call|Popen)|child_process|\bsystem\s*\(|shell_exec|eval\s*\(|os\.system)\b`)},
	{"ssrf", "CWE-918", regexp.MustCompile(`(?i)\b(http\.(Get|Post|Do)|requests\.(get|post)|urllib\.request|axios\.(get|post)|fetch\s*\(|HttpClient|RestTemplate)\b`)},
	{"path_traversal", "CWE-22", regexp.MustCompile(`(?i)\b(os\.(Open|ReadFile|Create)|open\s*\(|fs\.(readFile|createReadStream)|File\s*\(|sendFile|filepath\.Join|path\.join)\b`)},
	{"deserialization", "CWE-502", regexp.MustCompile(`(?i)\b(pickle\.loads?|yaml\.load\s*\(|Marshal\.load|ObjectInputStream|unserialize|JSON\.parse\s*\(\s*req)\b`)},
	{"xxe", "CWE-611", regexp.MustCompile(`(?i)\b(etree\.(parse|fromstring)|DocumentBuilder|SAXParser|xml\.Unmarshal|libxml)\b`)},
	{"xss", "CWE-79", regexp.MustCompile(`(?i)\b(innerHTML|dangerouslySetInnerHTML|template\.HTML|mark_safe|\|\s*safe|render_template_string)\b`)},
	{"open_redirect", "CWE-601", regexp.MustCompile(`(?i)\b(Redirect|redirect|sendRedirect|location\.href)\s*\(`)},
	{"idor", "CWE-639", regexp.MustCompile(`(?i)\.(FindByID|find_by_id|findById|get_object_or_404|findOne)\s*\(`)},
}

func extractSinks(lang, relPath, src string) []Sink {
	_ = lang
	lines := strings.Split(src, "\n")
	seen := map[string]struct{}{}
	var out []Sink

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || len(trimmed) > 500 {
			continue
		}
		for _, sp := range sinkPatterns {
			if !sp.re.MatchString(line) {
				continue
			}
			// One sink per kind per file: a consumer uses this to pick which
			// probes to prioritise, and forty copies of the same kind is
			// noise rather than signal.
			if _, dup := seen[sp.kind]; dup {
				continue
			}
			seen[sp.kind] = struct{}{}
			out = append(out, Sink{
				Kind: sp.kind, CWE: sp.cwe,
				File: relPath, Line: i + 1,
				Snippet: truncate(trimmed, 160),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// nextJSFileRoutes covers file-based routing, where the path is the file's
// location rather than anything written in the source.
func nextJSFileRoutes(root string, files []string) []Route {
	var out []Route
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		unix := filepath.ToSlash(rel)
		base := strings.ToLower(filepath.Base(unix))

		var prefix string
		switch {
		case strings.Contains(unix, "pages/api/"):
			prefix = "pages/api/"
		case strings.Contains(unix, "app/api/"):
			prefix = "app/api/"
		default:
			continue
		}
		idx := strings.Index(unix, prefix)
		routePath := unix[idx+len(prefix):]
		routePath = strings.TrimSuffix(routePath, filepath.Ext(routePath))
		routePath = strings.TrimSuffix(routePath, "/route")
		routePath = strings.TrimSuffix(routePath, "/index")
		if base == "index.js" || base == "index.ts" {
			routePath = strings.TrimSuffix(routePath, "index")
		}
		// [id] and [...slug] are Next.js path parameters.
		routePath = strings.NewReplacer("[...", "{", "[", "{", "]", "}").Replace(routePath)

		out = append(out, Route{
			Method:       "ANY",
			PathTemplate: normalizePath("/api/" + strings.Trim(routePath, "/")),
			Params:       pathParams(routePath),
			HandlerFile:  rel,
			HandlerLine:  1,
			Framework:    "nextjs",
		})
	}
	return out
}

// dedupeRoutes collapses the same (method, path) declared in several places,
// keeping the first declaration and merging sinks.
func dedupeRoutes(in []Route) []Route {
	type key struct{ method, path string }
	index := map[key]int{}
	var out []Route

	for _, r := range in {
		k := key{r.Method, r.PathTemplate}
		if at, ok := index[k]; ok {
			out[at].Sinks = mergeSinks(out[at].Sinks, r.Sinks)
			continue
		}
		index[k] = len(out)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PathTemplate != out[j].PathTemplate {
			return out[i].PathTemplate < out[j].PathTemplate
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func mergeSinks(a, b []Sink) []Sink {
	seen := map[string]struct{}{}
	for _, s := range a {
		seen[s.Kind] = struct{}{}
	}
	for _, s := range b {
		if _, ok := seen[s.Kind]; ok {
			continue
		}
		seen[s.Kind] = struct{}{}
		a = append(a, s)
	}
	return a
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
