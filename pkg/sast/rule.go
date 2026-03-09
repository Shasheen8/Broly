package sast

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Filter post-filters a query match by checking a named capture against a regex.
type Filter struct {
	Capture string `yaml:"capture"`
	Regex   string `yaml:"regex"`
	re      *regexp.Regexp
}

// Rule defines a single SAST detection.
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Language    string   `yaml:"language"`
	Severity    string   `yaml:"severity"`
	CWE         []string `yaml:"cwe"`
	Description string   `yaml:"description"`
	Message     string   `yaml:"message"`
	Query       string   `yaml:"query"`
	FindCapture string   `yaml:"find_capture"` // capture name to report; defaults to first
	Filter      []Filter `yaml:"filter,omitempty"`
	Fix         string   `yaml:"fix,omitempty"`
	References  []string `yaml:"references,omitempty"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func loadRulesFromFS(fsys fs.FS) ([]Rule, error) {
	var all []Rule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for i := range rf.Rules {
			for j := range rf.Rules[i].Filter {
				re, err := regexp.Compile(rf.Rules[i].Filter[j].Regex)
				if err != nil {
					return fmt.Errorf("rule %s filter regex: %w", rf.Rules[i].ID, err)
				}
				rf.Rules[i].Filter[j].re = re
			}
		}
		all = append(all, rf.Rules...)
		return nil
	})
	return all, err
}
