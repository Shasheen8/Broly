package changelog

import (
	"html"
	"regexp"
	"strings"
)

// RenderMarkdown converts the constrained markdown subset used by the
// changelog README into HTML: headings, paragraphs, fenced code blocks,
// bullet and numbered lists, horizontal rules, bold, inline code, and links.
// Input is HTML-escaped before any tags are injected.
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
		switch {
		case trimmed == "":
			flushPara()
			closeList()
		case strings.HasPrefix(trimmed, "### "):
			flushPara()
			closeList()
			out.WriteString("<h3>" + inline(trimmed[4:]) + "</h3>\n")
		case strings.HasPrefix(trimmed, "## "):
			flushPara()
			closeList()
			out.WriteString("<h2>" + inline(trimmed[3:]) + "</h2>\n")
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