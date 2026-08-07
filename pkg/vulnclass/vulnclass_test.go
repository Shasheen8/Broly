package vulnclass

import (
	"strings"
	"testing"

	"github.com/Shasheen8/Broly/pkg/core"
)

func TestLookup(t *testing.T) {
	c, ok := Lookup("idor")
	if !ok || c.Name != "idor" {
		t.Fatalf("Lookup(idor) = %v, %v", c, ok)
	}
	// Case-insensitive, trimmed.
	if _, ok := Lookup("  XSS "); !ok {
		t.Fatal("Lookup should be case-insensitive and trimmed")
	}
	// Flag names resolve too.
	if _, ok := Lookup("path-traversal"); !ok {
		t.Fatal("Lookup(path-traversal) failed")
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("Lookup(nope) should fail")
	}
}

func TestNames(t *testing.T) {
	names := Names()
	if len(names) != len(All) {
		t.Fatalf("Names() len = %d, want %d", len(names), len(All))
	}
	for _, n := range names {
		if _, ok := Lookup(n); !ok {
			t.Fatalf("Names() returned unresolvable name %q", n)
		}
	}
}

func TestMatchesByCWE(t *testing.T) {
	f := core.Finding{RuleID: "some.rule", CWE: []string{"cwe-89"}} // lowercase on finding side
	if !MatchesAny(f, []string{"sqli"}) {
		t.Fatal("CWE-89 finding should match sqli")
	}
	if MatchesAny(f, []string{"xss"}) {
		t.Fatal("CWE-89 finding should not match xss")
	}
}

func TestWordKeywordRequiresWholeToken(t *testing.T) {
	// "source" contains the substring "rce" but must NOT match the rce class.
	f := core.Finding{
		RuleID:      "test.rule",
		Title:       "User input flows from source to sink",
		Description: "A taint source was identified",
	}
	if MatchesAny(f, []string{"rce"}) {
		t.Fatal("'source' must not match word keyword 'rce'")
	}

	// A real RCE mention as its own token must match.
	f2 := core.Finding{Title: "Possible RCE via command injection"}
	if !MatchesAny(f2, []string{"rce"}) {
		t.Fatal("standalone 'RCE' token should match rce class")
	}
}

func TestMultiWordKeywordSubstring(t *testing.T) {
	f := core.Finding{Description: "User input concatenated into a SQL statement allows sql injection"}
	if !MatchesAny(f, []string{"sqli"}) {
		t.Fatal("multi-word keyword 'sql injection' should substring-match")
	}
}

func TestMultiWordKeywordWordBoundary(t *testing.T) {
	// "access controls" (plural) must NOT match the idor keyword "access control".
	f := core.Finding{Title: "SQL Injection", Description: "An attacker can bypass access controls to extract data."}
	if MatchesAny(f, []string{"idor"}) {
		t.Fatal("'access controls' must not match idor keyword 'access control'")
	}
	// A genuine idor mention of "access control" should still match.
	f2 := core.Finding{Title: "Missing access control on /api/Cards/:id", Description: "No ownership check."}
	if !MatchesAny(f2, []string{"idor"}) {
		t.Fatal("'access control' as its own phrase should match idor")
	}
	// "object references" (plural) must not match "object reference".
	f3 := core.Finding{Description: "The function returns object references for cleanup."}
	if MatchesAny(f3, []string{"idor"}) {
		t.Fatal("'object references' must not match idor keyword 'object reference'")
	}
}

func TestPunctuatedKeywordSubstring(t *testing.T) {
	f := core.Finding{Description: "subprocess.run(cmd, shell=True) with user input"}
	if !MatchesAny(f, []string{"rce"}) {
		t.Fatal("'shell=true' keyword should match after lowercasing")
	}
	f2 := core.Finding{Description: "yaml.load(data) on attacker input"}
	if !MatchesAny(f2, []string{"deserialization"}) {
		t.Fatal("'yaml.load' keyword should match deserialization")
	}
}

func TestMatchesAnyUnknownClass(t *testing.T) {
	f := core.Finding{CWE: []string{"CWE-89"}, Title: "sql injection"}
	if MatchesAny(f, []string{"nope"}) {
		t.Fatal("unknown class names must match nothing")
	}
}

func TestFilter(t *testing.T) {
	findings := []core.Finding{
		{RuleID: "a", CWE: []string{"CWE-89"}},
		{RuleID: "b", CWE: []string{"CWE-79"}},
		{RuleID: "c", Title: "hardcoded password in config"},
	}
	// Empty class list returns input unchanged.
	if got := Filter(findings, nil); len(got) != 3 {
		t.Fatalf("Filter(nil) len = %d, want 3", len(got))
	}
	got := Filter(findings, []string{"sqli", "xss"})
	if len(got) != 2 || got[0].RuleID != "a" || got[1].RuleID != "b" {
		t.Fatalf("Filter(sqli,xss) = %+v", got)
	}
	got = Filter(findings, []string{"hardcoded-secret"})
	if len(got) != 1 || got[0].RuleID != "c" {
		t.Fatalf("Filter(hardcoded-secret) = %+v", got)
	}
}

func TestFocusSection(t *testing.T) {
	if s := FocusSection(nil); s != "" {
		t.Fatalf("FocusSection(nil) = %q, want empty", s)
	}
	if s := FocusSection([]string{"nope"}); s != "" {
		t.Fatalf("FocusSection(unknown) = %q, want empty", s)
	}
	s := FocusSection([]string{"idor", "sqli"})
	for _, want := range []string{"Vulnerability Class Focus", "IDOR", "CWE-639", "SQL Injection", "CWE-89", "NO_FINDINGS"} {
		if !strings.Contains(s, want) {
			t.Fatalf("FocusSection missing %q:\n%s", want, s)
		}
	}
}

func TestInfoLines(t *testing.T) {
	if lines := InfoLines(nil); len(lines) != 0 {
		t.Fatalf("InfoLines(nil) len = %d, want 0", len(lines))
	}
	lines := InfoLines([]string{"xss"})
	if len(lines) != 2 {
		t.Fatalf("InfoLines(xss) len = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], "Cross-Site Scripting") || !strings.Contains(lines[0], "CWE-79") {
		t.Fatalf("InfoLines header malformed: %q", lines[0])
	}
}

func TestTokenize(t *testing.T) {
	tokens := tokenize("rce in source cwe-79")
	for _, want := range []string{"rce", "in", "source", "cwe", "79"} {
		if !tokens[want] {
			t.Fatalf("tokenize missing token %q (got %v)", want, tokens)
		}
	}
	if tokens["rce in source"] {
		t.Fatal("spaces must break tokens")
	}
}
