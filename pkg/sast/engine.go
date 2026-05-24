// Package sast provides AI-powered static application security testing.
package sast

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Shasheen8/Broly/pkg/cache"
	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	defaultModel       = "Qwen/Qwen3-Coder-Next-FP8"
	defaultMaxFileSize = 512 * 1024 // 512 KB
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
	fileCache    *cache.Cache
	incremental  bool
	sliceFiles   int
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

	s.sliceFiles = cfg.SASTSliceFiles
	if s.sliceFiles <= 0 {
		s.sliceFiles = defaultMaxContextFiles
	}

	s.incremental = cfg.Incremental
	if s.incremental {
		cachePath := cfg.CachePath
		if cachePath == "" {
			cachePath = cache.DefaultPath
		}
		c, err := cache.Load(cachePath)
		if err != nil {
			core.Warnf("could not load SAST cache: %v", err)
		} else {
			s.fileCache = c
		}
	}

	if os.Getenv("TOGETHER_API_KEY") == "" {
		core.Warnf("TOGETHER_API_KEY not set - SAST scanning skipped")
		s.apiKeySet = false
		return nil
	}
	s.apiKeySet = true

	model := cfg.AIModel
	if model == "" {
		model = defaultModel
	}
	s.client = newTogetherClient(model)

	return nil
}

func (s *SASTScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	if !s.apiKeySet {
		return nil
	}

	type fileJob struct {
		path  string
		root  string
		index *repoIndex
		lang  string
	}

	jobs := make(chan fileJob, 64)
	var wg sync.WaitGroup

	var (
		successMu    sync.Mutex
		successPaths []string
	)

	// Start workers.
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				if s.scanFile(ctx, job.index, job.root, job.path, job.lang, findings) && s.fileCache != nil {
					successMu.Lock()
					successPaths = append(successPaths, job.path)
					successMu.Unlock()
				}
			}
		}()
	}

	// Walk paths and enqueue files.
	for _, target := range paths {
		if ctx.Err() != nil {
			break
		}
		root := scanRoot(target)
		index := newRepoIndex(root)
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
				lang, ok = detectLangByName(name)
				if !ok {
					return nil
				}
			}
			if len(s.langFilter) > 0 && !s.langFilter[lang] {
				return nil
			}

			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > s.maxFileSize {
				return nil
			}

			// Incremental: skip files unchanged since last scan.
			if s.fileCache != nil && !s.fileCache.Changed(path) {
				return nil
			}

			jobs <- fileJob{path: path, root: root, index: index, lang: lang}
			return nil
		})
	}

	close(jobs)
	wg.Wait()

	// Persist cache only for files that were successfully scanned.
	if s.fileCache != nil {
		successMu.Lock()
		for _, path := range successPaths {
			s.fileCache.Update(path)
		}
		successMu.Unlock()
		_ = s.fileCache.Save()
	}

	return nil
}

func (s *SASTScanner) scanFile(ctx context.Context, index *repoIndex, root, path, lang string, findings chan<- core.Finding) bool {
	src, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	content := string(src)

	for _, hit := range runPrefilter(content) {
		f := core.Finding{
			Type:        core.ScanTypeSAST,
			RuleID:      "broly.prefilter." + slugify(hit.Pattern.Name),
			RuleName:    hit.Pattern.Name,
			Severity:    hit.Pattern.Severity,
			Title:       hit.Pattern.Name,
			Description: hit.Pattern.Name + " (" + hit.Pattern.CWE + ")",
			FilePath:    path,
			StartLine:   hit.Line,
			CWE:         []string{hit.Pattern.CWE},
			Tags:        []string{"sast", "prefilter", hit.Pattern.Category},
			Timestamp:   time.Now(),
		}
		f.ComputeFingerprint()
		select {
		case findings <- f:
		case <-ctx.Done():
			return false
		}
	}

	// AI scan: LLM-based deep analysis with a bounded multi-file slice.
	slice, err := buildAnalysisSlice(index, root, path, lang, content, s.sliceFiles, defaultMaxContextBytes)
	if err != nil {
		return false
	}
	prompt := buildPrompt(slice)

	response, err := s.client.complete(ctx, prompt)
	if err != nil {
		if ctx.Err() == nil {
			core.Warnf("SAST AI scan of %s: %v", path, err)
		}
		return false
	}

	parsed := parseLLMResponse(response)
	if len(parsed) == 0 && len(strings.TrimSpace(response)) > 0 && !strings.Contains(response, "NO_FINDINGS") {
		return false
	}
	for _, f := range attributeParsedFindings(slice, parsed) {
		f.Timestamp = time.Now()
		select {
		case findings <- f:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

func (s *SASTScanner) Close() error { return nil }
