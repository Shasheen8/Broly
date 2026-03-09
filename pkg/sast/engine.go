// Package sast provides AST-based static analysis via tree-sitter.
package sast

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/Shasheen8/Broly/pkg/core"
)

//go:embed rules/*.yml
var builtinRules embed.FS

type compiledRule struct {
	Rule
	query *sitter.Query
}

// SASTScanner implements core.Scanner using tree-sitter AST pattern matching.
type SASTScanner struct {
	rules        []compiledRule
	parsers      map[string]*sitter.Parser
	excludePaths map[string]bool
	maxFileSize  int64
}

func NewSASTScanner() *SASTScanner {
	return &SASTScanner{}
}

func (s *SASTScanner) Name() string        { return "sast" }
func (s *SASTScanner) Type() core.ScanType { return core.ScanTypeSAST }

func (s *SASTScanner) Init(cfg *core.Config) error {
	s.maxFileSize = cfg.MaxFileSize
	if s.maxFileSize == 0 {
		s.maxFileSize = 10 * 1024 * 1024 // 10MB
	}

	s.excludePaths = make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		s.excludePaths[p] = true
	}

	// Load rules from embedded FS or custom dir.
	var fsys fs.FS
	if cfg.SASTRulesDir != "" {
		fsys = os.DirFS(cfg.SASTRulesDir)
	} else {
		sub, err := fs.Sub(builtinRules, "rules")
		if err != nil {
			return fmt.Errorf("embed rules: %w", err)
		}
		fsys = sub
	}

	rules, err := loadRulesFromFS(fsys)
	if err != nil {
		return fmt.Errorf("load sast rules: %w", err)
	}

	// Optional language filter.
	langFilter := make(map[string]bool)
	for _, l := range cfg.Languages {
		langFilter[strings.ToLower(l)] = true
	}

	// Compile queries.
	for _, r := range rules {
		lang := getLang(r.Language)
		if lang == nil {
			continue
		}
		if len(langFilter) > 0 && !langFilter[r.Language] {
			continue
		}
		q, err := sitter.NewQuery([]byte(r.Query), lang)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: sast rule %s invalid query: %v\n", r.ID, err)
			continue
		}
		s.rules = append(s.rules, compiledRule{Rule: r, query: q})
	}

	// One parser per language, reused across files.
	s.parsers = make(map[string]*sitter.Parser)
	seen := make(map[string]bool)
	for _, r := range s.rules {
		if seen[r.Language] {
			continue
		}
		seen[r.Language] = true
		lang := getLang(r.Language)
		if lang == nil {
			continue
		}
		p := sitter.NewParser()
		p.SetLanguage(lang)
		s.parsers[r.Language] = p
	}

	return nil
}

func (s *SASTScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)
	for _, target := range paths {
		if ctx.Err() != nil {
			return nil
		}
		if err := s.scanPath(ctx, target, findings); err != nil {
			fmt.Fprintf(os.Stderr, "warning: sast scan of %s: %v\n", target, err)
		}
	}
	return nil
}

func (s *SASTScanner) scanPath(ctx context.Context, root string, findings chan<- core.Finding) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		name := d.Name()
		if s.excludePaths[name] || s.excludePaths[path] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(name))
		lang, ok := extToLang[ext]
		if !ok {
			return nil
		}

		parser, ok := s.parsers[lang]
		if !ok {
			return nil
		}

		var langRules []compiledRule
		for _, r := range s.rules {
			if r.Language == lang {
				langRules = append(langRules, r)
			}
		}
		if len(langRules) == 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > s.maxFileSize {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		if err := s.scanFile(ctx, path, src, parser, langRules, findings); err != nil {
			fmt.Fprintf(os.Stderr, "warning: sast file %s: %v\n", path, err)
		}
		return nil
	})
}

func (s *SASTScanner) scanFile(
	ctx context.Context,
	path string,
	src []byte,
	parser *sitter.Parser,
	rules []compiledRule,
	findings chan<- core.Finding,
) error {
	tree, err := parser.ParseCtx(ctx, nil, src)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	seen := make(map[string]bool)

	for _, rule := range rules {
		if ctx.Err() != nil {
			return nil
		}

		qc := sitter.NewQueryCursor()
		qc.Exec(rule.query, root)

		for {
			m, ok := qc.NextMatch()
			if !ok {
				break
			}
			if !applyFilters(m, rule.query, src, rule.Filter) {
				continue
			}

			node := findingNode(m, rule.query, rule.FindCapture)
			if node == nil {
				continue
			}

			startLine := int(node.StartPoint().Row) + 1
			endLine := int(node.EndPoint().Row) + 1
			snippet := strings.TrimSpace(string(src[node.StartByte():node.EndByte()]))
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}

			f := core.Finding{
				Type:        core.ScanTypeSAST,
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    core.ParseSeverity(rule.Severity),
				Title:       rule.Name,
				Description: rule.Message,
				FilePath:    path,
				StartLine:   startLine,
				EndLine:     endLine,
				Snippet:     snippet,
				CWE:         rule.CWE,
				References:  rule.References,
				Tags:        []string{"sast", rule.Language},
				Timestamp:   time.Now(),
			}
			f.ComputeFingerprint()

			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true

			select {
			case findings <- f:
			case <-ctx.Done():
				qc.Close()
				return nil
			}
		}
		qc.Close()
	}
	return nil
}

// applyFilters returns true if all filters match their named captures.
func applyFilters(m *sitter.QueryMatch, q *sitter.Query, src []byte, filters []Filter) bool {
	for _, f := range filters {
		matched := false
		for _, c := range m.Captures {
			if q.CaptureNameForId(c.Index) == f.Capture {
				text := string(src[c.Node.StartByte():c.Node.EndByte()])
				if f.re.MatchString(text) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// findingNode returns the node for the named capture (or first capture).
func findingNode(m *sitter.QueryMatch, q *sitter.Query, captureName string) *sitter.Node {
	if captureName != "" {
		for _, c := range m.Captures {
			if q.CaptureNameForId(c.Index) == captureName {
				return c.Node
			}
		}
	}
	if len(m.Captures) > 0 {
		return m.Captures[0].Node
	}
	return nil
}

func (s *SASTScanner) Close() error {
	for _, r := range s.rules {
		if r.query != nil {
			r.query.Close()
		}
	}
	for _, p := range s.parsers {
		p.Close()
	}
	return nil
}
