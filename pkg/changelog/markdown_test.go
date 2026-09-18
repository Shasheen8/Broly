package changelog

import (
	"strings"
	"testing"
)

func TestRenderMarkdownBasics(t *testing.T) {
	md := "# Title\n\nIntro with **bold** and `code` and a [link](https://example.com/a?b=1).\n\n## Section\n\n- item one\n- item two\n\n1. first\n2. second\n\n---\n\n```\nplain <code> block & stuff -> tags\n```\n"
	got := RenderMarkdown(md)
	for _, want := range []string{
		"<h1>Title</h1>",
		"<strong>bold</strong>",
		"<code>code</code>",
		`<a href="https://example.com/a?b=1" rel="noopener">link</a>`,
		"<h2>Section</h2>",
		"<ul>", "<li>item one</li>", "</ul>",
		"<ol>", "<li>first</li>", "</ol>",
		"<hr>",
		"<pre><code>plain &lt;code&gt; block &amp; stuff -&gt; tags\n</code></pre>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderMarkdownEscapesHTML(t *testing.T) {
	got := RenderMarkdown("para with <script>alert(1)</script> and **<b>tags</b>**\n")
	if strings.Contains(got, "<script>") || strings.Contains(got, "<b>") {
		t.Errorf("unescaped html in output: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("script should be escaped: %s", got)
	}
}

func TestRenderMarkdownCodeFenceOnly(t *testing.T) {
	got := RenderMarkdown("```\nunclosed fence\n")
	if !strings.Contains(got, "</code></pre>") {
		t.Errorf("unclosed fence should still close: %s", got)
	}
}