package changelog

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// canonicalSections is the display order used everywhere: good news first,
// warnings last.
var canonicalSections = []string{"New", "Improved", "Fixed", "Breaking"}

// Stats summarizes the size of the commit window behind an entry.
type Stats struct {
	Commits    int `yaml:"commits" json:"commits"`
	Insertions int `yaml:"insertions" json:"insertions"`
	Deletions  int `yaml:"deletions" json:"deletions"`
}

// CommitRef links a changelog item back to its commit.
type CommitRef struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// Item is a single user-facing change.
type Item struct {
	Title    string      `json:"title"`
	Detail   string      `json:"detail,omitempty"`
	Section  string      `json:"section"`
	Breaking bool        `json:"breaking"`
	Commits  []CommitRef `json:"commits,omitempty"`
}

// Section groups items under a heading.
type Section struct {
	Name  string `json:"name"`
	Items []Item `json:"items"`
}

// Entry is one release in the changelog.
type Entry struct {
	Version     string    `yaml:"version" json:"version"`
	Date        string    `yaml:"date" json:"date"`
	Title       string    `yaml:"title" json:"title"`
	Stats       Stats     `yaml:"stats" json:"stats"`
	Description string    `yaml:"-" json:"description"`
	Sections    []Section `yaml:"-" json:"sections"`
}

var (
	itemTitleRe  = regexp.MustCompile(`^\*\*(.+?)\*\*\s*(?:[—:-]|--)?\s*(.*)$`)
	linkShaRe    = regexp.MustCompile(`\[([0-9a-fA-F]{7,40})\]\((https?://[^\s)]+)\)`)
	bareShaRe    = regexp.MustCompile(`\(([0-9a-fA-F]{7,40})\)`)
	headingRe    = regexp.MustCompile(`^##\s+(.+?)\s*$`)
	headingUnder = regexp.MustCompile(`^[-=]+\s*$`)
)

// RenderMarkdown writes the entry as frontmatter + body markdown, the same
// format humans edit between generate and build.
func (e *Entry) RenderMarkdown() (string, error) {
	fm := map[string]any{
		"version": e.Version,
		"date":    e.Date,
		"title":   e.Title,
		"stats":   e.Stats,
	}
	head, err := yaml.Marshal(fm)
	if err != nil {
		return "", fmt.Errorf("encoding frontmatter: %w", err)
	}

	var b strings.Builder
	b.WriteString("---\n")
	b.Write([]byte(strings.TrimSuffix(string(head), "\n")))
	b.WriteString("\n---\n\n")

	for _, para := range strings.Split(strings.TrimSpace(e.Description), "\n\n") {
		para = strings.TrimSpace(para)
		if para != "" {
			b.WriteString(para)
			b.WriteString("\n\n")
		}
	}

	for _, name := range canonicalSections {
		s := e.section(name)
		if s == nil {
			continue
		}
		fmt.Fprintf(&b, "## %s\n", name)
		for _, it := range s.Items {
			b.WriteString("- **" + it.Title + "**")
			if it.Detail != "" {
				b.WriteString(" — " + it.Detail)
			}
			if len(it.Commits) > 0 {
				refs := make([]string, 0, len(it.Commits))
				for _, c := range it.Commits {
					if c.URL != "" {
						refs = append(refs, fmt.Sprintf("[%s](%s)", c.SHA, c.URL))
					} else {
						refs = append(refs, "("+c.SHA+")")
					}
				}
				b.WriteString(" (" + strings.Join(refs, ", ") + ")")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (e *Entry) section(name string) *Section {
	for i := range e.Sections {
		if e.Sections[i].Name == name {
			return &e.Sections[i]
		}
	}
	return nil
}

// ParseEntry reads the frontmatter + markdown body format that generate
// writes and humans edit.
func ParseEntry(data string) (*Entry, error) {
	rest := strings.ReplaceAll(data, "\r\n", "\n")
	if !strings.HasPrefix(rest, "---\n") {
		return nil, fmt.Errorf("missing frontmatter")
	}
	end := strings.Index(rest[4:], "\n---")
	if end < 0 {
		return nil, fmt.Errorf("unterminated frontmatter")
	}
	front := rest[4 : 4+end]
	body := strings.TrimLeft(rest[4+end+4:], "\n")

	e := &Entry{}
	if err := yaml.Unmarshal([]byte(front), e); err != nil {
		return nil, fmt.Errorf("parsing frontmatter: %w", err)
	}
	if e.Version == "" || e.Date == "" || e.Title == "" {
		return nil, fmt.Errorf("frontmatter needs version, date, and title")
	}
	if _, err := time.Parse("2006-01-02", e.Date); err != nil {
		return nil, fmt.Errorf("date must be YYYY-MM-DD, got %q", e.Date)
	}

	var desc []string
	current := -1 // index into e.Sections
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, " \t")
		if m := headingRe.FindStringSubmatch(line); m != nil {
			e.Sections = append(e.Sections, Section{Name: strings.TrimSpace(m[1])})
			current = len(e.Sections) - 1
			continue
		}
		if current < 0 {
			desc = append(desc, line)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") {
			continue
		}
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			e.Sections[current].Items = append(e.Sections[current].Items, parseItemLine(strings.TrimSpace(line[2:])))
		}
	}
	e.Description = joinParagraphs(desc)
	return e, nil
}

func joinParagraphs(lines []string) string {
	var paras []string
	var cur []string
	for _, l := range lines {
		if l == "" {
			if len(cur) > 0 {
				paras = append(paras, strings.Join(cur, " "))
				cur = nil
			}
			continue
		}
		cur = append(cur, l)
	}
	if len(cur) > 0 {
		paras = append(paras, strings.Join(cur, " "))
	}
	return strings.Join(paras, "\n\n")
}

func parseItemLine(line string) Item {
	it := Item{}
	if m := itemTitleRe.FindStringSubmatch(line); m != nil {
		it.Title = strings.TrimSpace(m[1])
		line = m[2]
	}

	var refs []CommitRef
	line = linkShaRe.ReplaceAllStringFunc(line, func(match string) string {
		m := linkShaRe.FindStringSubmatch(match)
		refs = append(refs, CommitRef{SHA: m[1], URL: m[2]})
		return ""
	})
	line = bareShaRe.ReplaceAllStringFunc(line, func(match string) string {
		m := bareShaRe.FindStringSubmatch(match)
		refs = append(refs, CommitRef{SHA: m[1]})
		return ""
	})
	line = strings.TrimRight(line, " \t")
	line = strings.TrimSuffix(line, "(")
	line = strings.TrimSpace(line)
	it.Detail = line
	it.Commits = refs
	return it
}

// Canonicalize orders sections and flags breaking items. It also fills
// missing commit URLs from the repo.
func (e *Entry) Canonicalize(repo RepoInfo) {
	for i := range e.Sections {
		e.Sections[i].Name = sectionDisplayName(e.Sections[i].Name)
		for j := range e.Sections[i].Items {
			e.Sections[i].Items[j].Section = e.Sections[i].Name
			e.Sections[i].Items[j].Breaking = strings.EqualFold(e.Sections[i].Name, "Breaking")
			for k := range e.Sections[i].Items[j].Commits {
				c := &e.Sections[i].Items[j].Commits[k]
				if c.URL == "" {
					c.URL = repo.CommitURL(c.SHA)
				}
			}
		}
	}

	ordered := make([]Section, 0, len(e.Sections))
	for _, name := range canonicalSections {
		if s := e.section(name); s != nil {
			ordered = append(ordered, *s)
		}
	}
	seen := map[string]bool{}
	for _, name := range canonicalSections {
		seen[name] = true
	}
	var rest []Section
	for _, s := range e.Sections {
		if !seen[s.Name] {
			rest = append(rest, s)
		}
	}
	e.Sections = append(ordered, rest...)
}

func sectionDisplayName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "new", "added", "features", "feature":
		return "New"
	case "improved", "improvements", "changed", "changes", "enhancements", "performance":
		return "Improved"
	case "fixed", "fixes", "bugfixes", "bug fixes", "bugfix":
		return "Fixed"
	case "breaking", "breaking changes", "removed", "deprecations", "deprecated":
		return "Breaking"
	}
	return strings.TrimSpace(name)
}

// Slug produces the filename-safe version of the title.
func (e *Entry) Slug() string {
	s := strings.ToLower(e.Title)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if out == "" {
		out = "untitled"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}