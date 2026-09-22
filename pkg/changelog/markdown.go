package changelog

import (
	"html"
	"regexp"
	"strings"
)

// Heading is a table-of-contents entry extracted from markdown.
type Heading struct {
	Level int    // 2 or 3
	Text  string
	ID    string
}

// ExtractHeadings returns the h2/h3 headings of a markdown document in
// order, with the same anchor IDs RenderMarkdown emits.
func ExtractHeadings(md string) []Heading {
	var out []Heading
	inCode := false
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "### "):
			out = append(out, Heading{Level: 3, Text: trimmed[4:], ID: headingSlug(trimmed[4:])})
		case strings.HasPrefix(trimmed, "## "):
			out = append(out, Heading{Level: 2, Text: trimmed[3:], ID: headingSlug(trimmed[3:])})
		}
	}
	return out
}

func headingSlug(s string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

var (
	videoSlotRe = regexp.MustCompile(`^<!-- video: (.+?) -->$`)
)

func videoSlot(line string) (string, bool) {
	if m := videoSlotRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// RenderMarkdown converts the constrained markdown subset used by the
// changelog README into HTML: headings, paragraphs, fenced code blocks,
// bullet and numbered lists, horizontal rules, bold, inline code, links,
// and video embed slots (`<!-- video: name -->` becomes a slot paragraph
// the page assembler replaces with a real player).
func RenderMarkdown(md string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var out strings.Builder
	var para []string
	var list string // "ul" or "ol" while open
	flushPara := func() {
		if len(para) > 0 {
			out.WriteString("<p>" + inline(strings.Join(para, " ")) + "</p>\n")
			para = nil
		}
	}
	closeList := func() {
		if list != "" {
			out.WriteString("</" + list + ">\n")
			list = ""
		}
	}
	inCode := false

	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			flushPara()
			closeList()
			if inCode {
				out.WriteString("</code></pre>\n")
				inCode = false
			} else {
				out.WriteString("<pre><code>")
				inCode = true
			}
			continue
		}
		if inCode {
			out.WriteString(html.EscapeString(line) + "\n")
			continue
		}

		trimmed := strings.TrimSpace(line)
		if name, ok := videoSlot(trimmed); ok {
			flushPara()
			closeList()
			out.WriteString("<p class=\"video-slot\" data-video=\"" + html.EscapeString(name) + "\"></p>\n")
			continue
		}
		switch {
		case trimmed == "":
			flushPara()
			closeList()
		case strings.HasPrefix(trimmed, "### "):
			flushPara()
			closeList()
			out.WriteString("<h3 id=\"" + headingSlug(trimmed[4:]) + "\">" + inline(trimmed[4:]) + "</h3>\n")
		case strings.HasPrefix(trimmed, "## "):
			flushPara()
			closeList()
			out.WriteString("<h2 id=\"" + headingSlug(trimmed[3:]) + "\">" + inline(trimmed[3:]) + "</h2>\n")
		case strings.HasPrefix(trimmed, "# "):
			flushPara()
			closeList()
			out.WriteString("<h1>" + inline(trimmed[2:]) + "</h1>\n")
		case trimmed == "---" || trimmed == "***":
			flushPara()
			closeList()
			out.WriteString("<hr>\n")
		case isListItem(trimmed):
			flushPara()
			kind := "ul"
			if trimmed[0] != '-' && trimmed[0] != '*' {
				kind = "ol"
			}
			if list != kind {
				closeList()
				list = kind
				out.WriteString("<" + kind + ">\n")
			}
			out.WriteString("<li>" + inline(listItemText(trimmed)) + "</li>\n")
		default:
			para = append(para, trimmed)
		}
	}
	if inCode {
		out.WriteString("</code></pre>\n")
	}
	flushPara()
	closeList()
	return out.String()
}

func isListItem(line string) bool {
	if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
		return true
	}
	for i := 0; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			continue
		}
		return strings.HasPrefix(line[i:], ". ") || strings.HasPrefix(line[i:], ") ")
	}
	return false
}

func listItemText(line string) string {
	if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
		return strings.TrimSpace(line[2:])
	}
	if i := strings.Index(line, ". "); i > 0 {
		return strings.TrimSpace(line[i+2:])
	}
	if i := strings.Index(line, ") "); i > 0 {
		return strings.TrimSpace(line[i+2:])
	}
	return line
}

var (
	mdBoldRe = regexp.MustCompile(`\*\*(.+?)\*\*`)
	mdCodeRe = regexp.MustCompile("`([^`]+)`")
	mdLinkRe = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+)\)`)
)

// inline escapes HTML and then applies the safe inline transforms.
func inline(s string) string {
	s = html.EscapeString(s)
	s = mdLinkRe.ReplaceAllString(s, `<a href="$2" rel="noopener">$1</a>`)
	s = mdBoldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = mdCodeRe.ReplaceAllString(s, "<code>$1</code>")
	return s
}