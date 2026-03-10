// Package sast provides AI-powered static application security testing.
package sast

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	defaultModel       = "Qwen/Qwen3-Coder-Next-FP8"
	defaultMaxFileSize = 10 * 1024 * 1024 // 10 MB
	defaultWorkers     = 4
)

// SASTScanner implements core.Scanner using AI-powered code analysis.
type SASTScanner struct {
	client       *togetherClient
	excludePaths map[string]bool
	langFilter   map[string]bool
	maxFileSize  int64
	workers      int
	apiKeySet    bool
}

func NewSASTScanner() *SASTScanner {
	return &SASTScanner{}
}

func (s *SASTScanner) Name() string        { return "sast" }
func (s *SASTScanner) Type() core.ScanType { return core.ScanTypeSAST }

func (s *SASTScanner) Init(cfg *core.Config) error {
	s.maxFileSize = cfg.MaxFileSize
	if s.maxFileSize == 0 {
		s.maxFileSize = defaultMaxFileSize
	}

	s.workers = cfg.Workers
	if s.workers <= 0 {
		s.workers = defaultWorkers
	}

	s.excludePaths = make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		s.excludePaths[p] = true
	}

	s.langFilter = make(map[string]bool)
	for _, l := range cfg.Languages {
		s.langFilter[strings.ToLower(l)] = true
	}

	apiKey := os.Getenv("TOGETHER_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "warning: TOGETHER_API_KEY not set — SAST scanning will be skipped")
		s.apiKeySet = false
		return nil
	}
	s.apiKeySet = true

	model := cfg.AIModel
	if model == "" {
		model = defaultModel
	}
	s.client = newTogetherClient(apiKey, model)

	return nil
}

func (s *SASTScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	if !s.apiKeySet {
		return nil
	}

	type fileJob struct {
		path string
		lang string
	}

	jobs := make(chan fileJob, 64)
	var wg sync.WaitGroup

	// Start workers.
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				s.scanFile(ctx, job.path, job.lang, findings)
			}
		}()
	}

	// Walk paths and enqueue files.
	for _, target := range paths {
		if ctx.Err() != nil {
			break
		}
		filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
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
			if len(s.langFilter) > 0 && !s.langFilter[lang] {
				return nil
			}

			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > s.maxFileSize {
				return nil
			}

			jobs <- fileJob{path: path, lang: lang}
			return nil
		})
	}

	close(jobs)
	wg.Wait()
	return nil
}

func (s *SASTScanner) scanFile(ctx context.Context, path, lang string, findings chan<- core.Finding) {
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}

	prompt := buildPrompt(path, lang, string(src))

	response, err := s.client.complete(ctx, prompt)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "warning: sast ai scan of %s: %v\n", path, err)
		}
		return
	}

	parsed := parseLLMResponse(path, response)
	for _, pf := range parsed {
		f := pf.toFinding(path)
		f.Timestamp = time.Now()
		select {
		case findings <- f:
		case <-ctx.Done():
			return
		}
	}
}

func (s *SASTScanner) Close() error { return nil }
