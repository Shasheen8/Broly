package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/changelog"
)

func changelogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "changelog",
		Short: "AI-generate changelog entries and build the changelog site",
		Long: `Generate user-facing changelog entries from git history with AI,
then build the static changelog site from the reviewed entries.

The workflow:
  1. broly changelog generate --since v1.66.0
       Prints a draft entry (frontmatter + markdown) to stdout.
  2. broly changelog generate --since v1.66.0 --write
       Saves the draft to changelog/entries/<date>-<slug>.md. Edit it —
       fix wording, add context the commits can't show, drop items.
  3. broly changelog build
       Renders changelog/site/changelog.json and feed.xml from every
       entry, ready for GitHub Pages.

The audience for entries is end users of the tool, not maintainers:
new capabilities, fixed bugs, and anything that can break workflows.
Commits are filtered and grouped by the model; maintainer context can
be passed with --notes.`,
	}

	cmd.AddCommand(changelogGenerateCmd())
	cmd.AddCommand(changelogBuildCmd())
	return cmd
}

func changelogGenerateCmd() *cobra.Command {
	var (
		sinceRef  string
		untilRef  string
		days      int
		notes     string
		version   string
		product   string
		write     bool
		entries   string
		aiModel   string
		maxCommit int
	)

	cmd := &cobra.Command{
		Use:   "generate [repo]",
		Short: "Generate a changelog entry draft from recent commits",
		Long: `Collect commits since a tag (or within the last N days), hand them to
the model with diffs and file context, and draft a changelog entry for
the tool's end users.

Without --write the draft prints to stdout, so it can be reviewed in the
terminal or piped anywhere. With --write it is saved under the entries
directory as editable markdown — the review step is part of the workflow:
the model summarizes, you correct and enrich, the site publishes what
you approved.

EXAMPLES
  broly changelog generate                          # since the latest tag
  broly changelog generate --since v1.65.0          # explicit tag or rev
  broly changelog generate --days 7                 # last 7 days
  broly changelog generate --notes "shipped for DEFCON demo"
  broly changelog generate --version v1.67.0 --write`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoDir := "."
			if len(args) == 1 {
				repoDir = args[0]
			}
			if days > 0 && cmd.Flags().Changed("since") {
				return fmt.Errorf("--days and --since are mutually exclusive")
			}
			if days > 0 && untilRef != "" {
				return fmt.Errorf("--days and --until are mutually exclusive")
			}

			repo, err := changelog.RepoInfoFor(repoDir)
			if err != nil {
				return err
			}

			var h *changelog.History
			switch {
			case days > 0:
				fmt.Fprintf(os.Stderr, "  collecting commits from the last %d days\n", days)
				h, err = changelog.CollectDays(repoDir, days, maxCommit)
			default:
				if sinceRef == "" {
					sinceRef = changelog.LatestTag(repoDir)
					if sinceRef == "" {
						return fmt.Errorf("no tags found; use --since <rev> or --days N")
					}
				}
				fmt.Fprintf(os.Stderr, "  collecting commits %s..%s\n", sinceRef, untilLabel(untilRef))
				h, err = changelog.CollectSince(repoDir, sinceRef, untilRef, maxCommit)
				h.Since = sinceRef
			}
			if err != nil {
				return err
			}
			if len(h.Commits) == 0 {
				fmt.Println("  no commits in this range — nothing to generate")
				return nil
			}
			h.FillDiffs(repoDir)
			fmt.Fprintf(os.Stderr, "  %d commits, +%d -%d lines\n", len(h.Commits), h.Insertions, h.Deletions)

			client, ok := ai.New(aiModel)
			if !ok {
				return fmt.Errorf("changelog generation needs TOGETHER_API_KEY (same key as the SAST and triage features)")
			}
			fmt.Fprintf(os.Stderr, "  asking %s to draft the entry...\n", client.ModelName())

			e, err := changelog.Generate(cmd.Context(), client, repo, h, product, notes)
			if err != nil {
				return err
			}
			if version != "" {
				e.Version = version
			} else if h.HeadTag != "" {
				e.Version = h.HeadTag
			} else {
				e.Version = "Unreleased"
			}
			// The entry date is the date of the newest commit in the
			// window: backfilled releases keep their real release date.
			if len(h.Commits) > 0 {
				e.Date = h.Commits[0].Date
			} else {
				e.Date = time.Now().Format("2006-01-02")
			}
			e.Stats = changelog.Stats{Commits: len(h.Commits), Insertions: h.Insertions, Deletions: h.Deletions}
			e.Canonicalize(repo)

			markdown, err := e.RenderMarkdown()
			if err != nil {
				return err
			}

			if !write {
				fmt.Print(markdown)
				return nil
			}

			if err := os.MkdirAll(entries, 0o755); err != nil {
				return fmt.Errorf("creating %s: %w", entries, err)
			}
			path := filepath.Join(entries, e.Date+"-"+e.Slug()+".md")
			if err := os.WriteFile(path, []byte(markdown), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Fprintf(os.Stderr, "  wrote %s\n", path)
			fmt.Fprintf(os.Stderr, "  review it, then run `broly changelog build` and commit\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&sinceRef, "since", "", "Collect commits since this tag or revision (default: latest tag)")
	cmd.Flags().StringVar(&untilRef, "until", "", "Collect commits up to this revision (default: HEAD; use for backfilling historical releases)")
	cmd.Flags().IntVar(&days, "days", 0, "Collect commits from the last N days instead of since a tag")
	cmd.Flags().StringVar(&notes, "notes", "", "Maintainer context for the model: why changes shipped, what they mean")
	cmd.Flags().StringVar(&version, "version", "", "Release version for the entry (default: tag on HEAD, or 'Unreleased')")
	cmd.Flags().StringVar(&product, "product", "a developer tool", "One-line description of the product for the model")
	cmd.Flags().BoolVar(&write, "write", false, "Write the draft to the entries directory instead of stdout")
	cmd.Flags().StringVar(&entries, "entries", "changelog/entries", "Directory drafts are written to")
	cmd.Flags().StringVar(&aiModel, "ai-model", "", fmt.Sprintf("Together.ai model (default: %s)", ai.DefaultModel))
	cmd.Flags().IntVar(&maxCommit, "max-commits", 150, "Maximum commits to consider")
	return cmd
}

func untilLabel(until string) string {
	if until == "" {
		return "HEAD"
	}
	return until
}

func changelogBuildCmd() *cobra.Command {
	var (
		entries string
		siteDir string
		baseURL string
	)

	cmd := &cobra.Command{
		Use:   "build [repo]",
		Short: "Build the changelog site data from reviewed entries",
		Long: `Parse every markdown entry in the entries directory and render
changelog.json and feed.xml for the static changelog site.

Run this after adding or editing an entry, then commit everything:
GitHub Pages (see .github/workflows/pages.yml) re-runs this build on
push and deploys the site directory.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoDir := "."
			if len(args) == 1 {
				repoDir = args[0]
			}
			repo, err := changelog.RepoInfoFor(repoDir)
			if err != nil {
				return err
			}
			if baseURL == "" {
				baseURL = changelog.SiteURL(repo)
			}
			return changelog.BuildSite(entries, siteDir, baseURL, repo)
		},
	}

	cmd.Flags().StringVar(&entries, "entries", "changelog/entries", "Directory containing entry markdown files")
	cmd.Flags().StringVar(&siteDir, "site", "changelog/site", "Directory the site data is written to")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Public URL of the site (default: derived from origin remote)")
	return cmd
}