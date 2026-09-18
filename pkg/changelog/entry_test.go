package changelog

import (
	"strings"
	"testing"
)

func TestRenderParseRoundTrip(t *testing.T) {
	e := &Entry{
		Version: "v1.67.0",
		Date:    "2026-09-18",
		Title:   "Routes extraction and faster scans",
		Stats:   Stats{Commits: 12, Insertions: 431, Deletions: 205},
		Description: "This release adds a routes subcommand and hardens\ntriage output.\n\nIt also fixes several report bugs.",
		Sections: []Section{
			{Name: "Fixed", Items: []Item{
				{Title: "IaC findings not rendered in table output", Detail: "IaC findings now appear in the CLI table.", Commits: []CommitRef{{SHA: "1270b0f", URL: "https://github.com/a/b/commit/1270b0f"}}},
			}},
			{Name: "New", Items: []Item{
				{Title: "Routes subcommand", Detail: "Extracts declared HTTP routes and dangerous sinks.", Commits: []CommitRef{{SHA: "be5f9b6", URL: "https://github.com/a/b/commit/be5f9b6"}}},
			}},
		},
	}
	e.Canonicalize(RepoInfo{FullName: "a/b", URL: "https://github.com/a/b"})

	md, err := e.RenderMarkdown()
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	back, err := ParseEntry(md)
	if err != nil {
		t.Fatalf("parse: %v\n---\n%s", err, md)
	}
	if back.Version != e.Version || back.Date != e.Date || back.Title != e.Title {
		t.Errorf("meta mismatch: %+v", back)
	}
	if back.Stats != e.Stats {
		t.Errorf("stats mismatch: %+v vs %+v", back.Stats, e.Stats)
	}
	if !strings.Contains(back.Description, "This release adds a routes subcommand") {
		t.Errorf("description lost paragraphs: %q", back.Description)
	}
	if len(back.Sections) != 2 {
		t.Fatalf("want 2 sections, got %d", len(back.Sections))
	}
	if back.Sections[0].Name != "New" {
		t.Errorf("New should come first after canonicalize, got %s", back.Sections[0].Name)
	}
	item := back.Sections[0].Items[0]
	if item.Title != "Routes subcommand" {
		t.Errorf("title: %q", item.Title)
	}
	if !strings.Contains(item.Detail, "Extracts declared HTTP routes") {
		t.Errorf("detail: %q", item.Detail)
	}
	if len(item.Commits) != 1 || item.Commits[0].SHA != "be5f9b6" || item.Commits[0].URL == "" {
		t.Errorf("commits: %+v", item.Commits)
	}
}

func TestParseEntryTolerantFormats(t *testing.T) {
	md := `---
version: v1.5.0
date: 2026-01-01
title: A title
stats:
  commits: 3
  insertions: 10
  deletions: 2
---

Narrative line one
continued on the same paragraph.

Second paragraph.

## New
* **Star bullets** — Work too. ([abc1234](https://x/commit/abc1234))

## Fixed
- No bold title, just detail with a bare sha (def5678)
- **Bare detail without separator** has this text.

## Weird Section
- Custom section survives.
`
	e, err := ParseEntry(md)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Description != "Narrative line one continued on the same paragraph.\n\nSecond paragraph." {
		t.Errorf("description: %q", e.Description)
	}
	if len(e.Sections) != 3 {
		t.Fatalf("sections: %d", len(e.Sections))
	}
	if e.Sections[0].Name != "New" || len(e.Sections[0].Items) != 1 {
		t.Fatalf("New section: %+v", e.Sections[0])
	}
	if e.Sections[0].Items[0].Commits[0].SHA != "abc1234" {
		t.Errorf("star bullet commit: %+v", e.Sections[0].Items[0].Commits)
	}
	fixed := e.Sections[1]
	if fixed.Items[0].Title != "" || !strings.Contains(fixed.Items[0].Detail, "bare sha") {
		t.Errorf("untitled item: %+v", fixed.Items[0])
	}
	if fixed.Items[0].Commits[0].SHA != "def5678" {
		t.Errorf("bare sha: %+v", fixed.Items[0].Commits)
	}
	if !strings.HasPrefix(fixed.Items[1].Title, "Bare detail") {
		t.Errorf("separatorless title: %+v", fixed.Items[1])
	}
	if e.Sections[2].Name != "Weird Section" {
		t.Errorf("custom section: %+v", e.Sections[2])
	}
}

func TestParseEntryRejectsBadInput(t *testing.T) {
	if _, err := ParseEntry("no frontmatter here"); err == nil {
		t.Error("expected error for missing frontmatter")
	}
	if _, err := ParseEntry("---\nversion: v1\n---\nbody"); err == nil {
		t.Error("expected error for missing date/title")
	}
	if _, err := ParseEntry("---\nversion: v1\ndate: not-a-date\ntitle: x\n---\nbody"); err == nil {
		t.Error("expected error for bad date")
	}
}

func TestCanonicalizeFlagsBreaking(t *testing.T) {
	e := &Entry{
		Sections: []Section{
			{Name: "Breaking Changes", Items: []Item{{Title: "Removed a flag"}}},
			{Name: "added", Items: []Item{{Title: "New thing"}}},
		},
	}
	e.Canonicalize(RepoInfo{})
	if e.Sections[0].Name != "New" {
		t.Errorf("added should map to New first: %+v", e.Sections[0])
	}
	breaking := e.Sections[1]
	if breaking.Name != "Breaking" || !breaking.Items[0].Breaking {
		t.Errorf("breaking normalization: %+v", breaking)
	}
}

func TestParseModelEntry(t *testing.T) {
	resp := "```json\n{\"title\":\"T\",\"description\":\"D\",\"items\":[{\"section\":\"fix\",\"title\":\"F\",\"detail\":\"d\",\"commits\":[\"abc1234\",\"deadbeef\"]}]}\n```"
	me, err := parseModelEntry(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if me.Title != "T" || len(me.Items) != 1 || me.Items[0].Section != "fix" {
		t.Errorf("parsed: %+v", me)
	}
	if _, err := parseModelEntry("no json at all"); err == nil {
		t.Error("expected error for no JSON")
	}
}

func TestEntryFromModelFiltersUnknownSHAs(t *testing.T) {
	h := &History{Commits: []Commit{{SHA: "abcdef1234567890", Short: "abcdef123"}}}
	me := &modelEntry{
		Title:       "T",
		Description: "D",
		Items: []modelItem{
			{Section: "new", Title: "Real", Commits: []string{"abcdef123", "fffffffff"}},
		},
	}
	e := entryFromModel(me, RepoInfo{FullName: "a/b", URL: "https://github.com/a/b"}, h)
	if len(e.Sections[0].Items[0].Commits) != 1 {
		t.Errorf("unknown sha should be dropped: %+v", e.Sections[0].Items[0])
	}
	if e.Sections[0].Items[0].Commits[0].URL != "https://github.com/a/b/commit/abcdef123" {
		t.Errorf("commit url: %+v", e.Sections[0].Items[0].Commits)
	}
}