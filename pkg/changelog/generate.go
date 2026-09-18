package changelog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Shasheen8/Broly/pkg/ai"
)

type modelItem struct {
	Section string   `json:"section"`
	Title   string   `json:"title"`
	Detail  string   `json:"detail"`
	Commits []string `json:"commits"`
}

type modelEntry struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Items       []modelItem  `json:"items"`
}

// Generate asks the model to turn a commit window into an entry draft.
// product describes the tool in one line ("a CLI-first code security
// scanner"); notes carries freeform maintainer context that is not visible
// in the git history.
func Generate(ctx context.Context, client *ai.Client, repo RepoInfo, h *History, product, notes string) (*Entry, error) {
	prompt := buildPrompt(repo, h, product, notes)
	resp, err := client.Complete(ctx, prompt, 4096)
	if err != nil {
		return nil, fmt.Errorf("changelog generation: %w", err)
	}
	me, err := parseModelEntry(resp)
	if err != nil {
		return nil, err
	}
	return entryFromModel(me, repo, h), nil
}

func buildPrompt(repo RepoInfo, h *History, product, notes string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `You are writing a public changelog entry for %q, %s.

AUDIENCE
Developers who use this tool but do not work on it. They care about new
capabilities, changed behavior, fixed bugs, and anything that can break
their workflows (flags, commands, config, output formats, exit codes).
They do NOT care about internal refactors, CI chores, dependency bumps,
or doc reorganization, unless those change behavior they can observe.

TASK
Summarize the commits below into a changelog entry. Group related commits
into a single item where they tell one story. Skip commits that are pure
maintenance with no user-visible effect. If everything in the window is
noise, return few items. Never invent changes.

PUNCTUATION
Use plain ASCII punctuation only. Never use em dashes in any output text;
use colons, commas, or periods instead.

FORMAT
Respond with JSON only, no markdown fences, matching:
{
  "title": "short release headline, 3-6 words, no version number",
  "description": "2-4 sentence narrative explaining what this release is
                  about and why it matters to users; plain prose, no markdown",
  "items": [
    {
      "section": "new" | "improved" | "fixed" | "breaking",
      "title": "imperative, specific; e.g. 'Adds a routes subcommand'",
      "detail": "1-2 sentences: what changed and what it means for the user",
      "commits": ["short-sha", "short-sha"]
    }
  ]
}
Use "breaking" only for changes that can break existing workflows.
Reference commit SHAs exactly as given below.

`, repo.FullName, product)
	if notes != "" {
		fmt.Fprintf(&b, "MAINTAINER NOTES\n%s\n\n", notes)
	}
	if h.Truncated {
		fmt.Fprintf(&b, "NOTE: the window below was truncated to the most recent %d commits.\n\n", len(h.Commits))
	}
	b.WriteString("COMMITS (oldest first)\n")
	for i := len(h.Commits) - 1; i >= 0; i-- {
		c := h.Commits[i]
		fmt.Fprintf(&b, "\n%s %s %s\n", c.Short, c.Date, c.Subject)
		if c.Body != "" {
			body := c.Body
			if len(body) > 400 {
				body = body[:400] + "..."
			}
			for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
				fmt.Fprintf(&b, "  | %s\n", line)
			}
		}
		files := c.Files
		if len(files) > maxFilesPerCommit {
			files = append(files[:maxFilesPerCommit:maxFilesPerCommit], fmt.Sprintf("(+%d more)", len(c.Files)-maxFilesPerCommit))
		}
		fmt.Fprintf(&b, "  files: %s\n", strings.Join(files, ", "))
		fmt.Fprintf(&b, "  +%d -%d\n", c.Insertions, c.Deletions)
		if c.Diff != "" {
			b.WriteString("  diff:\n")
			for _, line := range strings.Split(c.Diff, "\n") {
				fmt.Fprintf(&b, "    %s\n", line)
			}
		}
	}
	return b.String()
}

func parseModelEntry(resp string) (*modelEntry, error) {
	resp = strings.TrimSpace(resp)
	resp = strings.TrimPrefix(resp, "```json")
	resp = strings.TrimPrefix(resp, "```")
	resp = strings.TrimSuffix(resp, "```")
	start := strings.Index(resp, "{")
	end := strings.LastIndex(resp, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("model response contained no JSON")
	}
	me := &modelEntry{}
	if err := json.Unmarshal([]byte(resp[start:end+1]), me); err != nil {
		return nil, fmt.Errorf("parsing model JSON: %w", err)
	}
	if len(me.Items) == 0 {
		return nil, fmt.Errorf("model returned no changelog items")
	}
	return me, nil
}

func entryFromModel(me *modelEntry, repo RepoInfo, h *History) *Entry {
	e := &Entry{
		Title:       strings.TrimSpace(me.Title),
		Description: strings.TrimSpace(me.Description),
	}
	known := make(map[string]string, len(h.Commits)) // short-sha(lower) -> short
	for _, c := range h.Commits {
		known[strings.ToLower(c.Short)] = c.Short
	}
	sanitize := func(sha string) (string, bool) {
		sha = strings.ToLower(strings.TrimSpace(sha))
		if sha == "" {
			return "", false
		}
		if k, ok := known[sha]; ok {
			return k, true
		}
		for k := range known {
			if strings.HasPrefix(k, sha) {
				return known[k], true
			}
		}
		return "", false
	}

	for _, mi := range me.Items {
		it := Item{
			Title:   strings.TrimSpace(mi.Title),
			Detail:  strings.TrimSpace(mi.Detail),
			Section: sectionDisplayName(mi.Section),
		}
		it.Breaking = strings.EqualFold(it.Section, "Breaking")
		added := 0
		for _, sha := range mi.Commits {
			if added >= 3 {
				break
			}
			if s, ok := sanitize(sha); ok {
				it.Commits = append(it.Commits, CommitRef{SHA: s, URL: repo.CommitURL(s)})
				added++
			}
		}
		e.addSectionItem(it)
	}
	e.Canonicalize(repo)
	return e
}

func (e *Entry) addSectionItem(it Item) {
	for i := range e.Sections {
		if e.Sections[i].Name == it.Section {
			e.Sections[i].Items = append(e.Sections[i].Items, it)
			return
		}
	}
	e.Sections = append(e.Sections, Section{Name: it.Section, Items: []Item{it}})
}