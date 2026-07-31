// Package vulnclass provides a registry of vulnerability classes Broly can focus
// a scan on (e.g. --idor, --xss), the matching logic that filters findings to
// those classes, the SAST prompt focus section, and terminal info blurbs.
package vulnclass

import (
	"fmt"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

// Class describes one focusable vulnerability class.
type Class struct {
	Name     string   // canonical name (also the config-file value)
	Flag     string   // CLI flag name
	Title    string   // display name with CWE refs
	CWEs     []string // associated CWE IDs, uppercase "CWE-NNN"
	Keywords []string // matchers against rule id/name/title/description/tags
	Hint     string   // SAST prompt focus guidance for the LLM
	Info     string   // capability blurb printed when the class is selected
}

// All is the registry of focusable vulnerability classes, in display order.
var All = []Class{
	{
		Name:  "idor",
		Flag:  "idor",
		Title: "IDOR — Insecure Direct Object Reference",
		CWEs:  []string{"CWE-639", "CWE-862", "CWE-863"},
		Keywords: []string{
			"idor", "bola", "insecure direct object", "object reference",
			"object level authorization", "missing authorization", "broken access control",
			"authorization bypass", "access control", "ownership check", "ownership",
			"unauthorized access", "tenant",
		},
		Hint: "- Look for handlers, resolvers, or routes that fetch or mutate an object using a user-supplied identifier (path param, query param, body field) WITHOUT verifying the authenticated caller owns or may access that object.\n" +
			"- Trace whether any ownership/tenancy check (e.g. comparing resource.userID to the session user, or an authorize()/can() call) exists between the input and the data access. Absence of that check IS the vulnerability.\n" +
			"- Sequential/predictable IDs (numeric IDs, UUIDs copied from another user's response) make it exploitable; note this in Risk.",
		Info: "Detects endpoints that fetch or mutate an object by user-supplied ID without verifying the caller owns it. LLM data-flow analysis spots the missing ownership check; agentic triage traces cross-file authorization before verdict.",
	},
	{
		Name:  "bola",
		Flag:  "bola",
		Title: "BOLA — Broken Object Level Authorization",
		CWEs:  []string{"CWE-639", "CWE-862", "CWE-863"},
		Keywords: []string{
			"bola", "idor", "object level authorization", "insecure direct object",
			"object reference", "missing authorization", "broken access control",
			"authorization bypass", "access control", "ownership check", "ownership",
			"unauthorized access", "tenant",
		},
		Hint: "- BOLA is the API variant of IDOR: look for API endpoints where an object ID from the path, query, or body reaches a data access (DB query, file read, RPC) without a per-object authorization check against the caller's identity.\n" +
			"- Confirm whether the handler uses ONLY the caller-supplied ID to authorize (or nothing at all), rather than the authenticated session context.\n" +
			"- Check sibling endpoints: if GET /objects/{id} checks ownership but PUT/DELETE do not, report the inconsistent ones.",
		Info: "API variant of IDOR: object IDs from path/query/body reach data access without per-object authorization. Broly traces request-scoped user identity versus resource ownership across files.",
	},
	{
		Name:  "sqli",
		Flag:  "sqli",
		Title: "SQL Injection",
		CWEs:  []string{"CWE-89"},
		Keywords: []string{
			"sql injection", "sqli", "sql string", "sql f-string", "sql format",
			"sql concat", "nosql injection", "query concatenation",
		},
		Hint: "- Look for user-controllable input concatenated, interpolated, or formatted into SQL/NoSQL queries (f-strings, template literals, + operator, fmt.Sprintf).\n" +
			"- Parameterized queries, prepared statements, and ORM bind parameters are safe; string-built queries are not, even when escaped manually.\n" +
			"- Trace the input from the request/entry point to the query execution call.",
		Info: "Detects user-controlled input concatenated or interpolated into SQL queries. Deterministic prefilter patterns plus LLM source-to-sink confirmation.",
	},
	{
		Name:  "xss",
		Flag:  "xss",
		Title: "Cross-Site Scripting",
		CWEs:  []string{"CWE-79", "CWE-80"},
		Keywords: []string{
			"xss", "cross-site scripting", "cross site scripting", "innerhtml",
			"outerhtml", "document.write", "dangerouslysetinnerhtml", "html injection",
			"template injection",
		},
		Hint: "- Look for unencoded user input reaching HTML/JS sinks: innerHTML, outerHTML, document.write, dangerouslySetInnerHTML, template rendering without context-specific escaping.\n" +
			"- textContent and context-aware auto-escaping are safe; raw HTML assignment is not.\n" +
			"- Stored flows (input saved then rendered later) count — trace both directions.",
		Info: "Detects unencoded user input reaching HTML/JS sinks (innerHTML, document.write, template rendering). Prefilter plus LLM source-to-sink tracing.",
	},
	{
		Name:  "rce",
		Flag:  "rce",
		Title: "Remote Code / Command Execution",
		CWEs:  []string{"CWE-78", "CWE-94", "CWE-77", "CWE-95"},
		Keywords: []string{
			"remote code execution", "command injection", "code injection", "rce",
			"os command", "shell command", "shell=true", "eval injection",
			"command execution", "exec(", "shell injection",
		},
		Hint: "- Look for user-controllable input reaching OS command execution (os.system, subprocess with shell=True, exec.Command, child_process.exec) or code evaluation (eval, exec, new Function, vm.runInContext).\n" +
			"- Argument-array invocations without shell are safe; string-built commands and shell=True are not.\n" +
			"- Trace the input from entry point to the exec/eval sink; note any quoting or sanitization and whether it is sufficient.",
		Info: "Detects user input reaching shell execution or eval-style sinks without allowlisting. Prefilter catches concat-into-exec; the LLM traces indirect flows.",
	},
	{
		Name:  "ssrf",
		Flag:  "ssrf",
		Title: "Server-Side Request Forgery",
		CWEs:  []string{"CWE-918"},
		Keywords: []string{
			"ssrf", "server-side request forgery", "server side request forgery",
			"unvalidated url", "url fetch", "remote url",
		},
		Hint: "- Look for user-controllable URLs, hosts, or ports reaching outbound HTTP/RPC calls (requests.get, fetch, http.Get, axios) without a host allowlist.\n" +
			"- Flag reachability of internal ranges and the cloud metadata endpoint (the link-local address used by cloud instance metadata services) when the host is attacker-controlled.\n" +
			"- Redirect-following can bypass naive prefix checks; note it in Risk.",
		Info: "Detects user-controlled URLs or hosts reaching outbound requests without an allowlist, including cloud metadata reachability.",
	},
	{
		Name:  "xxe",
		Flag:  "xxe",
		Title: "XML External Entity Injection",
		CWEs:  []string{"CWE-611"},
		Keywords: []string{
			"xxe", "xml external entity", "external entity", "xml injection",
			"doctype", "entity expansion",
		},
		Hint: "- Look for XML parsers processing untrusted documents with external entities or DTD processing enabled (lxml without resolve_entities=False, DocumentBuilderFactory without FEATURE_SECURE_PROCESSING, xml.etree with custom parsers).\n" +
			"- Note impact: local file disclosure, SSRF via entity URIs, or billion-laughs DoS.",
		Info: "Detects XML parsers processing untrusted documents with external entities enabled.",
	},
	{
		Name:  "path-traversal",
		Flag:  "path-traversal",
		Title: "Path Traversal",
		CWEs:  []string{"CWE-22", "CWE-23", "CWE-73"},
		Keywords: []string{
			"path traversal", "directory traversal", "path concatenation",
			"traversal", "dot-dot", "zip slip", "arbitrary file",
		},
		Hint: "- Look for user-controllable input concatenated or joined into filesystem paths (open, readFile, sendFile, os.Open) without canonicalization plus a base-directory prefix check.\n" +
			"- ../ sequences, absolute paths, and symlink escapes are the exploitation primitives.\n" +
			"- Archive extraction (zip/tar) with unsanitized entry names is zip-slip — report it here.",
		Info: "Detects user input concatenated into filesystem paths without canonicalization and a base-directory prefix check.",
	},
	{
		Name:  "deserialization",
		Flag:  "deserialization",
		Title: "Insecure Deserialization",
		CWEs:  []string{"CWE-502"},
		Keywords: []string{
			"deserialization", "deserialisation", "pickle", "unserialize",
			"unmarshalling", "objectinputstream", "yaml.load", "marshal",
		},
		Hint: "- Look for attacker-controlled data decoded by powerful deserializers: pickle.loads, yaml.load without SafeLoader, ObjectInputStream.readObject, unserialize, gob on untrusted bytes.\n" +
			"- JSON decoding is safe; class-instantiating decoders are not.\n" +
			"- Note the gadget/execution impact in Risk when the decoder can trigger code execution.",
		Info: "Detects pickle/unserialize-style decoding of attacker-controlled data that can lead to code execution.",
	},
	{
		Name:  "open-redirect",
		Flag:  "open-redirect",
		Title: "Open Redirect",
		CWEs:  []string{"CWE-601"},
		Keywords: []string{
			"open redirect", "unvalidated redirect", "url redirect", "redirect",
		},
		Hint: "- Look for user-controllable values used as redirect targets (Location header, res.redirect, window.location) without an allowlist of hosts or relative-path enforcement.\n" +
			"- Note phishing/oauth-token-theft impact in Risk.",
		Info: "Detects unvalidated user input used as redirect targets, enabling phishing and token theft.",
	},
	{
		Name:  "weak-crypto",
		Flag:  "weak-crypto",
		Title: "Weak Cryptography",
		CWEs:  []string{"CWE-327", "CWE-328", "CWE-330", "CWE-321"},
		Keywords: []string{
			"weak hash", "weak crypto", "md5", "sha1", "ecb", "insecure random",
			"math.random", "weak cipher", "des(", "rc4", "hardcoded key",
		},
		Hint: "- Look for MD5/SHA1 used for security purposes (passwords, tokens, signatures), ECB mode ciphers, DES/RC4, and non-CSPRNG randomness (Math.random, rand without crypto seed) for security tokens.\n" +
			"- Hashing for non-security purposes (cache keys, checksums, git objects) is NOT a finding.\n" +
			"- Hardcoded cryptographic keys belong here too.",
		Info: "Detects MD5/SHA1 for security purposes, ECB mode, and non-CSPRNG randomness for tokens.",
	},
	{
		Name:  "hardcoded-secret",
		Flag:  "hardcoded-secret",
		Title: "Hardcoded Secrets",
		CWEs:  []string{"CWE-798", "CWE-321", "CWE-259"},
		Keywords: []string{
			"hardcoded secret", "hardcoded password", "hardcoded credential",
			"hardcoded api key", "hardcoded token", "private key block", "jwt secret",
			"aws access key", "api key", "secret key", "access token", "password",
		},
		Hint: "- Look for credentials hardcoded in source: passwords, API keys, tokens, private keys, connection strings with embedded credentials.\n" +
			"- Obvious placeholders (REPLACE_ME, YOUR_KEY_HERE, all-zero, documented example values) are NOT findings.\n" +
			"- Environment variables and secret-manager references are safe.",
		Info: "Detects credentials in source via 487 Titus rules plus regex prefilter; AI false-positive filtering and source-API validation available.",
	},
}

// Lookup returns the class with the given canonical name or flag.
func Lookup(name string) (Class, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, c := range All {
		if c.Name == name || c.Flag == name {
			return c, true
		}
	}
	return Class{}, false
}

// Names returns the canonical names of all registered classes.
func Names() []string {
	names := make([]string, 0, len(All))
	for _, c := range All {
		names = append(names, c.Name)
	}
	return names
}

// MatchesAny reports whether the finding belongs to at least one of the named
// classes. Unknown class names match nothing.
func MatchesAny(f core.Finding, names []string) bool {
	for _, name := range names {
		c, ok := Lookup(name)
		if !ok {
			continue
		}
		if matchesClass(f, c) {
			return true
		}
	}
	return false
}

// Filter keeps only findings belonging to at least one named class.
// A nil/empty class list returns the input unchanged.
func Filter(findings []core.Finding, names []string) []core.Finding {
	if len(names) == 0 {
		return findings
	}
	filtered := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		if MatchesAny(f, names) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func matchesClass(f core.Finding, c Class) bool {
	for _, fc := range f.CWE {
		fc = strings.ToUpper(strings.TrimSpace(fc))
		for _, cw := range c.CWEs {
			if fc == cw {
				return true
			}
		}
	}

	text := strings.ToLower(strings.Join([]string{
		f.RuleID, f.RuleName, f.Title, f.Description, strings.Join(f.Tags, " "),
	}, " "))
	tokens := tokenize(text)
	for _, kw := range c.Keywords {
		if isWordKeyword(kw) {
			if tokens[kw] {
				return true
			}
			continue
		}
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

// isWordKeyword reports whether a keyword is a single alphanumeric word, in
// which case it must match a whole token (so "rce" cannot match "source").
func isWordKeyword(kw string) bool {
	for _, r := range kw {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return len(kw) > 0
}

func tokenize(text string) map[string]bool {
	tokens := make(map[string]bool)
	start := -1
	for i, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			tokens[text[start:i]] = true
			start = -1
		}
	}
	if start >= 0 {
		tokens[text[start:]] = true
	}
	return tokens
}

// FocusSection builds the SAST prompt section that focuses the LLM on the
// named classes. Returns "" when no valid classes are named.
func FocusSection(names []string) string {
	var sb strings.Builder
	for _, name := range names {
		c, ok := Lookup(name)
		if !ok {
			continue
		}
		if sb.Len() == 0 {
			sb.WriteString("\n## Vulnerability Class Focus:\n\n")
			sb.WriteString("The operator requested a focused hunt for the vulnerability classes below. Report ONLY findings in these classes; if none are present, respond NO_FINDINGS.\n")
		}
		fmt.Fprintf(&sb, "\n**%s** (%s):\n%s\n", c.Title, strings.Join(c.CWEs, ", "), c.Hint)
	}
	return sb.String()
}

// InfoLines returns terminal blurbs describing each named class and how Broly
// detects it, for stderr output at scan start.
func InfoLines(names []string) []string {
	var lines []string
	for _, name := range names {
		c, ok := Lookup(name)
		if !ok {
			continue
		}
		lines = append(lines,
			fmt.Sprintf("  focus: %s (%s)", c.Title, strings.Join(c.CWEs, ", ")),
			"         "+c.Info,
		)
	}
	return lines
}
