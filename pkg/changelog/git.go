// Package changelog implements AI-generated changelog entries and the static
// site data built from them.
package changelog

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxCommits = 150
	maxFilesPerCommit = 30
	maxDiffBytes     = 1200
	maxDiffSnippets   = 6
)

// Commit is a single commit with the context the LLM needs to describe it.
type Commit struct {
	SHA        string
	Short      string
	Author     string
	Date       string
	Subject    string
	Body       string
	Files      []string
	Insertions int
	Deletions  int
	Diff       string
}

// RepoInfo identifies the repository entries link back to.
type RepoInfo struct {
	FullName string // "owner/repo"
	URL      string // "https://github.com/owner/repo"
}

// History is the commit window a changelog entry summarizes.
type History struct {
	Since      string // tag or date the window starts at
	IsTag      bool
	HeadTag    string // tag on HEAD if any, "" otherwise
	Commits    []Commit
	Insertions int
	Deletions  int
	Truncated  bool
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

// RepoInfoFor resolves the origin remote of the repo at dir into an https
// URL and owner/repo name.
func RepoInfoFor(dir string) (RepoInfo, error) {
	remote, err := git(dir, "remote", "get-url", "origin")
	if err != nil {
		return RepoInfo{}, fmt.Errorf("could not read origin remote: %w", err)
	}
	return repoInfoFromRemote(strings.TrimSpace(remote)), nil
}

func repoInfoFromRemote(remote string) RepoInfo {
	remote = strings.TrimSuffix(strings.TrimSpace(remote), ".git")
	switch {
	case strings.HasPrefix(remote, "git@"):
		// git@github.com:owner/repo -> https://github.com/owner/repo
		if i := strings.Index(remote, ":"); i > 0 {
			remote = "https://" + remote[i+1:]
		}
	case strings.HasPrefix(remote, "ssh://"):
		remote = strings.Replace(remote, "ssh://", "https://", 1)
	}
	name := strings.TrimPrefix(remote, "https://")
	name = strings.TrimPrefix(name, "http://")
	if i := strings.Index(name, "/"); i >= 0 {
		name = name[i+1:]
	} else {
		name = ""
	}
	return RepoInfo{FullName: name, URL: remote}
}

// LatestTag returns the most recent reachable tag, or "" if none exist.
func LatestTag(dir string) string {
	tag, err := git(dir, "describe", "--tags", "--abbrev=0")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(tag)
}

// HeadTag returns the exact tag on HEAD, or "" if HEAD is untagged.
func HeadTag(dir string) string {
	tag, err := git(dir, "describe", "--tags", "--exact-match", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(tag)
}

// CollectSince gathers commits between two revisions (until defaults to HEAD).
func CollectSince(dir, since, until string, maxCommits int) (*History, error) {
	if _, err := git(dir, "rev-parse", "--verify", since+"^{commit}"); err != nil {
		return nil, fmt.Errorf("unknown revision %q: %w", since, err)
	}
	if until == "" {
		until = "HEAD"
	} else if _, err := git(dir, "rev-parse", "--verify", until+"^{commit}"); err != nil {
		return nil, fmt.Errorf("unknown revision %q: %w", until, err)
	}
	if maxCommits <= 0 {
		maxCommits = defaultMaxCommits
	}
	h, err := collect(dir, []string{since + ".." + until}, maxCommits)
	if err != nil {
		return nil, err
	}
	if until == "HEAD" {
		h.HeadTag = HeadTag(dir)
	}
	return h, nil
}

// CollectDays gathers commits from the last N days.
func CollectDays(dir string, days int, maxCommits int) (*History, error) {
	if days <= 0 {
		return nil, fmt.Errorf("--days must be positive")
	}
	since := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	if maxCommits <= 0 {
		maxCommits = defaultMaxCommits
	}
	h, err := collect(dir, []string{"--since=" + since + " 00:00:00"}, maxCommits)
	if err != nil {
		return nil, err
	}
	h.Since = since
	h.HeadTag = HeadTag(dir)
	return h, nil
}

func collect(dir string, logArgs []string, maxCommits int) (*History, error) {
	args := append([]string{"log"}, logArgs...)
	args = append(args,
		"--no-merges",
		"--date=short",
		"--pretty=format:%x1e%H%x00%h%x00%an%x00%ad%x00%s%x00%b",
		"--numstat",
	)
	out, err := git(dir, args...)
	if err != nil {
		return nil, fmt.Errorf("reading git log: %w", err)
	}

	h := &History{}
	for _, rec := range strings.Split(out, "\x1e") {
		if rec == "" || strings.TrimSpace(rec) == "" {
			continue
		}
		c, err := parseCommitRecord(rec)
		if err != nil {
			continue
		}
		h.Commits = append(h.Commits, c)
		h.Insertions += c.Insertions
		h.Deletions += c.Deletions
		if len(h.Commits) == maxCommits {
			h.Truncated = true
			break
		}
	}
	if len(h.Commits) > maxCommits {
		h.Commits = h.Commits[:maxCommits]
		h.Truncated = true
	}
	return h, nil
}

func parseCommitRecord(rec string) (Commit, error) {
	lines := strings.Split(rec, "\n")
	fieldLine := -1
	for i, line := range lines {
		if strings.Contains(line, "\x00") {
			fieldLine = i
			break
		}
	}
	if fieldLine < 0 {
		return Commit{}, fmt.Errorf("malformed commit record")
	}
	fields := strings.Split(lines[fieldLine], "\x00")
	if len(fields) < 6 {
		return Commit{}, fmt.Errorf("malformed commit record")
	}
	c := Commit{
		SHA:     fields[0],
		Short:   fields[1],
		Author:  fields[2],
		Date:    fields[3],
		Subject: strings.TrimSpace(fields[4]),
		Body:    strings.TrimSpace(fields[5]),
	}
	if len(c.Short) > 9 {
		c.Short = c.Short[:9]
	}
	for _, line := range lines[fieldLine+1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		add, del := parts[0], parts[1]
		if add != "-" {
			if n, err := strconv.Atoi(add); err == nil {
				c.Insertions += n
			}
		}
		if del != "-" {
			if n, err := strconv.Atoi(del); err == nil {
				c.Deletions += n
			}
		}
		c.Files = append(c.Files, parts[2])
	}
	return c, nil
}

// FillDiffs attaches trimmed diffs to the most user-facing commits so the
// model can see what actually changed, not just the commit message.
func (h *History) FillDiffs(dir string) {
	type scored struct {
		idx   int
		score int
	}
	scoredCommits := make([]scored, 0, len(h.Commits))
	for i, c := range h.Commits {
		s := 0
		switch {
		case strings.HasPrefix(strings.ToLower(c.Subject), "feat"):
			s += 4
		case strings.HasPrefix(strings.ToLower(c.Subject), "fix"):
			s += 3
		case strings.HasPrefix(strings.ToLower(c.Subject), "perf"):
			s += 2
		}
		for _, kw := range []string{"breaking", "remove", "rename", "deprecat"} {
			if strings.Contains(strings.ToLower(c.Subject), kw) {
				s += 5
				break
			}
		}
		for _, f := range c.Files {
			if strings.HasPrefix(f, "cmd/") || strings.Contains(f, ".broly.yaml") {
				s += 3
				break
			}
		}
		if s > 0 {
			scoredCommits = append(scoredCommits, scored{i, s})
		}
	}
	sort.Slice(scoredCommits, func(a, b int) bool {
		return scoredCommits[a].score > scoredCommits[b].score
	})
	if len(scoredCommits) > maxDiffSnippets {
		scoredCommits = scoredCommits[:maxDiffSnippets]
	}
	for _, sc := range scoredCommits {
		out, err := git(dir, "show", h.Commits[sc.idx].SHA, "--format=", "--unified=0")
		if err != nil {
			continue
		}
		diff := strings.TrimSpace(out)
		if len(diff) > maxDiffBytes {
			diff = diff[:maxDiffBytes] + "\n... (truncated)"
		}
		if diff != "" {
			h.Commits[sc.idx].Diff = diff
		}
	}
}

// CommitURL returns the GitHub URL for a short or full SHA.
func (r RepoInfo) CommitURL(sha string) string {
	if r.URL == "" {
		return ""
	}
	if len(sha) > 9 {
		sha = sha[:9]
	}
	return r.URL + "/commit/" + sha
}