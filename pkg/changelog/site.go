package changelog

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type siteRepo struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Site string `json:"site"`
}

type siteData struct {
	Repo        siteRepo `json:"repo"`
	GeneratedAt string   `json:"generated_at"`
	Entries     []*Entry `json:"entries"`
}

// SiteURL derives the GitHub Pages URL for a repo: github.com/O/R ->
// https://O.github.io/R.
func SiteURL(repo RepoInfo) string {
	parts := strings.Split(repo.FullName, "/")
	if len(parts) != 2 {
		return repo.URL
	}
	return fmt.Sprintf("https://%s.github.io/%s", strings.ToLower(parts[0]), parts[1])
}

// LoadEntries parses every entry in dir, sorted newest first. An empty
// directory yields an empty slice, not an error. The site renders a
// friendly empty state.
func LoadEntries(dir string) ([]*Entry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var entries []*Entry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Name(), err)
		}
		e, err := ParseEntry(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name(), err)
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(a, b int) bool {
		if entries[a].Date != entries[b].Date {
			return entries[a].Date > entries[b].Date
		}
		return strings.Compare(entries[a].Version, entries[b].Version) > 0
	})
	return entries, nil
}

// BuildSite writes changelog.json and feed.xml into outDir from the
// entries in entriesDir. It also renders the README into about.html so
// the site's About page and the repo README stay in sync from one source.
func BuildSite(entriesDir, outDir, baseURL string, repo RepoInfo, readmePath string) error {
	entries, err := LoadEntries(entriesDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		e.Canonicalize(repo)
	}
	if baseURL == "" {
		baseURL = SiteURL(repo)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", outDir, err)
	}

	data := siteData{
		Repo:        siteRepo{Name: repo.FullName, URL: repo.URL, Site: baseURL},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:     entries,
	}
	j, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding changelog.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "changelog.json"), append(j, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing changelog.json: %w", err)
	}

	feed, err := renderFeed(data, baseURL)
	if err != nil {
		return fmt.Errorf("rendering feed: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "feed.xml"), []byte(feed), 0o644); err != nil {
		return fmt.Errorf("writing feed.xml: %w", err)
	}

	about := 0
	if readmePath != "" {
		readme, err := os.ReadFile(readmePath)
		if err != nil {
			fmt.Printf("  note: skipping about page (%s not found)\n", readmePath)
		} else {
			html := renderAboutPage(string(readme), data, baseURL)
			if err := os.WriteFile(filepath.Join(outDir, "about.html"), []byte(html), 0o644); err != nil {
				return fmt.Errorf("writing about.html: %w", err)
			}
			about = 1
		}
	}
	fmt.Printf("  built changelog.json (%d entries), feed.xml, and about.html (%d) in %s\n", len(entries), about, outDir)
	return nil
}

func renderFeed(d siteData, baseURL string) (string, error) {
	name := d.Repo.Name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<rss version="2.0"><channel>` + "\n")
	fmt.Fprintf(&b, "  <title>%s changelog</title>\n", xmlEscape(name))
	fmt.Fprintf(&b, "  <link>%s</link>\n", xmlEscape(baseURL))
	fmt.Fprintf(&b, "  <description>Release notes and changes for %s</description>\n", xmlEscape(name))
	for _, e := range d.Entries {
		fmt.Fprintf(&b, "  <item>\n")
		fmt.Fprintf(&b, "    <title>%s: %s</title>\n", xmlEscape(e.Version), xmlEscape(e.Title))
		fmt.Fprintf(&b, "    <link>%s#%s</link>\n", xmlEscape(baseURL), xmlEscape(anchorID(e.Version)))
		fmt.Fprintf(&b, "    <guid>%s#%s</guid>\n", xmlEscape(baseURL), xmlEscape(anchorID(e.Version)))
		if t, err := time.Parse("2006-01-02", e.Date); err == nil {
			fmt.Fprintf(&b, "    <pubDate>%s</pubDate>\n", t.Format(time.RFC1123Z))
		}
		if e.Description != "" {
			fmt.Fprintf(&b, "    <description>%s</description>\n", xmlEscape(e.Description))
		}
		fmt.Fprintf(&b, "  </item>\n")
	}
	b.WriteString("</channel></rss>\n")
	return b.String(), nil
}

func renderAboutPage(readme string, d siteData, baseURL string) string {
	name := d.Repo.Name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	var toc strings.Builder
	for _, h := range ExtractHeadings(readme) {
		class := "toc-h2"
		if h.Level == 3 {
			class = "toc-h3"
		}
		fmt.Fprintf(&toc, "        <a class=\"%s\" href=\"#%s\">%s</a>\n", class, h.ID, html.EscapeString(h.Text))
	}

	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + htmlPageTitle(name) + ` Changelog: About</title>
  <meta name="description" content="How this changelog is made: the tool, the review workflow, and the design decisions behind it.">
  <link rel="icon" href="broly-logo.png" type="image/png">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="site-header">
    <div class="glow" aria-hidden="true"></div>
    <div class="header-inner">
      <a class="brand" href="index.html" title="Back to the changelog">
        <img src="broly-logo.png" alt="` + htmlPageTitle(name) + ` logo" width="44" height="44">
        <span>
          <strong>` + htmlPageTitle(name) + `</strong>
          <em>Changelog</em>
        </span>
      </a>
      <nav class="header-actions">
        <a class="action" href="index.html">Changelog</a>
        <a class="action" href="feed.xml" title="RSS feed">RSS</a>
        <a class="action" href="` + d.Repo.URL + `" title="Source on GitHub">GitHub</a>
      </nav>
    </div>
    <p class="tagline">Why this changelog exists, and how it is made.</p>
  </header>

  <div class="about-layout">
    <aside class="toc" aria-label="Table of contents">
      <p class="toc-title">On this page</p>
` + toc.String() + `    </aside>

    <main class="about">
    ` + RenderMarkdown(readme) + `
    </main>
  </div>

  <footer class="site-footer">
    <p>This page is rendered from <code>changelog/README.md</code> by <code>broly changelog build</code>, so it can never drift from the repo.</p>
  </footer>

  <script>
  (function () {
    var links = Array.prototype.slice.call(document.querySelectorAll('.toc a'));
    var byId = {};
    links.forEach(function (l) { byId[l.getAttribute('href').slice(1)] = l; });
    var current = null;
    function setActive(id) {
      if (id === current) return;
      current = id;
      links.forEach(function (l) { l.classList.remove('active'); });
      if (byId[id]) byId[id].classList.add('active');
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) setActive(e.target.id);
      });
    }, { rootMargin: '-15% 0px -75% 0px' });
    document.querySelectorAll('.about h2[id], .about h3[id]').forEach(function (h) { observer.observe(h); });
    if (links.length) setActive(links[0].getAttribute('href').slice(1));
  })();
  </script>
</body>
</html>
`
}

func htmlPageTitle(name string) string {
	if name == "" {
		return "Broly"
	}
	return name
}

func anchorID(version string) string {
	v := strings.ToLower(version)
	v = strings.ReplaceAll(v, ".", "-")
	return strings.ReplaceAll(v, " ", "-")
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}