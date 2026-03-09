package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/report"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/secrets"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	root := &cobra.Command{
		Use:   "broly",
		Short: "Broly - Berserker Product Security Tool",
		Long: `Broly is a production-grade security scanner combining SAST, SCA, and
Secrets scanning into a single fast binary. Built in Go for speed.`,
		SilenceUsage: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(validateCmd())

	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}

func scanCmd() *cobra.Command {
	var (
		outputFormat   string
		outputFile     string
		enableSAST     bool
		enableSCA      bool
		enableSecrets  bool
		workers        int
		minSeverity    string
		excludePaths   []string
		secretsRules   string
		disableRedact  bool
		offline        bool
		quiet          bool
	)

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan targets for security findings",
		Long: `Run SAST, SCA, and Secrets scanning against the specified paths.
By default all scanners are enabled and the current directory is scanned.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"."}
			}

			allDisabled := !enableSAST && !enableSCA && !enableSecrets
			if allDisabled {
				enableSAST = true
				enableSCA = true
				enableSecrets = true
			}

			cfg := &core.Config{
				Targets:          args,
				EnableSAST:       enableSAST,
				EnableSCA:        enableSCA,
				EnableSecrets:    enableSecrets,
				Workers:          workers,
				OutputFormat:     outputFormat,
				OutputFile:       outputFile,
				MinSeverity:      core.ParseSeverity(minSeverity),
				ExcludePaths:     excludePaths,
				SecretsRulesDir:  secretsRules,
				DisableRedaction: disableRedact,
				Offline:          offline,
				Quiet:            quiet,
			}

			return runScan(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, sarif")
	flags.StringVarP(&outputFile, "output", "o", "", "Write output to file (default: stdout)")
	flags.BoolVar(&enableSAST, "sast", false, "Enable SAST scanning")
	flags.BoolVar(&enableSCA, "sca", false, "Enable SCA scanning")
	flags.BoolVar(&enableSecrets, "secrets", false, "Enable Secrets scanning")
	flags.IntVar(&workers, "workers", 8, "Number of parallel workers")
	flags.StringVar(&minSeverity, "min-severity", "info", "Minimum severity: info, low, medium, high, critical")
	flags.StringSliceVar(&excludePaths, "exclude", nil, "Paths to exclude from scanning")
	flags.StringVar(&secretsRules, "secrets-rules", "", "Custom secrets rules directory")
	flags.BoolVar(&disableRedact, "no-redact", false, "Disable secret redaction in output")
	flags.BoolVar(&offline, "offline", false, "Run SCA in offline mode (skip OSV API)")
	flags.BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")

	return cmd
}

func runScan(cfg *core.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "broly v%s — scanning %s\n", version, strings.Join(cfg.Targets, ", "))
		scanners := make([]string, 0, 3)
		if cfg.EnableSecrets {
			scanners = append(scanners, "secrets")
		}
		if cfg.EnableSCA {
			scanners = append(scanners, "sca")
		}
		if cfg.EnableSAST {
			scanners = append(scanners, "sast")
		}
		fmt.Fprintf(os.Stderr, "scanners: %s | workers: %d\n\n", strings.Join(scanners, ", "), cfg.Workers)
	}

	report.Version = version
	orch := orchestrator.New(cfg)

	if cfg.EnableSecrets {
		orch.Register(secrets.NewSecretsScanner())
	}
	if cfg.EnableSCA {
		orch.Register(sca.NewSCAScanner())
	}
	if cfg.EnableSAST {
		orch.Register(sast.NewSASTScanner())
	}

	start := time.Now()
	result, err := orch.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	result.Duration = time.Since(start)

	formatter, err := report.GetFormatter(cfg.OutputFormat)
	if err != nil {
		return err
	}

	var w *os.File
	if cfg.OutputFile != "" {
		w, err = os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	if err := formatter.Format(w, result); err != nil {
		return fmt.Errorf("format output: %w", err)
	}

	if len(result.Findings) > 0 {
		os.Exit(1)
	}
	return nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("broly %s (commit: %s)\n", version, commit)
		},
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-rules",
		Short: "Validate secrets rules (compile patterns, run tests)",
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := secrets.LoadDefaultRules()
			if err != nil {
				return err
			}

			errs := secrets.ValidateRules(rules)
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "  FAIL: %s\n", e)
				}
				return fmt.Errorf("%d rule validation errors", len(errs))
			}

			fmt.Printf("  All %d rules validated successfully.\n", len(rules))
			return nil
		},
	}
}
