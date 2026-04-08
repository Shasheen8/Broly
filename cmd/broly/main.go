package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Shasheen8/Broly/pkg/container"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/license"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/report"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sbom"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/secrets"
)

var (
	version = "dev"
	commit  = "none"

	errFindings = errors.New("findings detected")
)

func main() {
	root := &cobra.Command{
		Use:   "broly",
		Short: "Broly - Berserker Product Security Tool",
		Long: `Broly is a production-grade security scanner combining SAST, SCA, and
Secrets scanning into a single fast binary. Built in Go for speed.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(sbomCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(validateCmd())

	if err := root.Execute(); err != nil {
		if errors.Is(err, errFindings) {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Scan completed with findings. Broly is exiting with code 1 so shells and CI can detect the result.")
			fmt.Fprintln(os.Stderr, "Tip: use --format json or --format sarif for machine-readable output.")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "broly failed: %v\n", err)
		os.Exit(2)
	}
}

func scanCmd() *cobra.Command {
	var (
		configFile          string
		outputFormat        string
		outputFile          string
		enableSAST          bool
		enableSCA           bool
		enableSecrets       bool
		workers             int
		minSeverity         string
		excludePaths        []string
		secretsRules        string
		disableRedact       bool
		validateSecrets     bool
		offline             bool
		quiet               bool
		aiModel             string
		packageIntelligence bool
		packageRegistryMode string
		npmRegistryURL      string
		pypiRegistryURL     string
		cratesRegistryURL   string
		languages           []string
		aiFilterSecrets     bool
		aiSCAReachability   bool
		aiTriage            bool
		explain             bool
		baselineFile        string
		incremental         bool
		cachePath           string
		containerImage      string
		sastSliceFiles      int
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

			// Start with defaults from config file (if present).
			cfg := loadConfigFile(configFile)
			cfg.Targets = args

			// CLI flags override config file values where explicitly set.
			f := cmd.Flags()
			if f.Changed("format") {
				cfg.OutputFormat = outputFormat
			} else if cfg.OutputFormat == "" {
				cfg.OutputFormat = outputFormat
			}
			if f.Changed("output") {
				cfg.OutputFile = outputFile
			}
			if f.Changed("workers") {
				cfg.Workers = workers
			} else if cfg.Workers == 0 {
				cfg.Workers = workers
			}
			if f.Changed("min-severity") {
				sev, ok := core.ParseSeverityStrict(minSeverity)
				if !ok {
					return fmt.Errorf("unknown severity %q (use: info, low, medium, high, critical)", minSeverity)
				}
				cfg.MinSeverity = sev
			} else if cfg.MinSeverity == 0 {
				cfg.MinSeverity = core.ParseSeverity(minSeverity)
			}
			if f.Changed("exclude") {
				cfg.ExcludePaths = excludePaths
			}
			if f.Changed("secrets-rules") {
				cfg.SecretsRulesDir = secretsRules
			}
			if f.Changed("no-redact") {
				cfg.DisableRedaction = disableRedact
			}
			if f.Changed("validate") {
				cfg.ValidateSecrets = validateSecrets
			}
			if f.Changed("offline") {
				cfg.Offline = offline
			}
			if f.Changed("quiet") || f.Changed("q") {
				cfg.Quiet = quiet
			}
			if f.Changed("ai-model") {
				cfg.AIModel = aiModel
			}
			if f.Changed("package-intelligence") {
				cfg.PackageIntelligence = packageIntelligence
			}
			if f.Changed("package-registry-mode") {
				cfg.PackageRegistryMode = packageRegistryMode
			}
			if f.Changed("npm-registry-url") {
				cfg.NPMRegistryURL = npmRegistryURL
			}
			if f.Changed("pypi-registry-url") {
				cfg.PyPIRegistryURL = pypiRegistryURL
			}
			if f.Changed("crates-registry-url") {
				cfg.CratesRegistryURL = cratesRegistryURL
			}
			if f.Changed("languages") {
				cfg.Languages = languages
			}
			if f.Changed("ai-filter-secrets") {
				cfg.AIFilterSecrets = aiFilterSecrets
			}
			if f.Changed("ai-sca-reachability") {
				cfg.AISCAReachability = aiSCAReachability
			}
			if f.Changed("ai-triage") {
				cfg.AITriage = aiTriage
			}
			if f.Changed("explain") {
				cfg.Explain = explain
			}
			if f.Changed("baseline") {
				cfg.BaselineFile = baselineFile
			}
			if f.Changed("incremental") {
				cfg.Incremental = incremental
			}
			if f.Changed("cache-path") {
				cfg.CachePath = cachePath
			}
			if f.Changed("container") {
				cfg.ContainerImage = containerImage
			}
			if f.Changed("sast-slice-files") {
				cfg.SASTSliceFiles = sastSliceFiles
			}

			// Scanner enable flags: CLI always wins; if none set and config has none, enable all.
			cliSAST := f.Changed("sast")
			cliSCA := f.Changed("sca")
			cliSecrets := f.Changed("secrets")

			if cliSAST {
				cfg.EnableSAST = enableSAST
			}
			if cliSCA {
				cfg.EnableSCA = enableSCA
			}
			if cliSecrets {
				cfg.EnableSecrets = enableSecrets
			}

			if !cfg.EnableSAST && !cfg.EnableSCA && !cfg.EnableSecrets {
				cfg.EnableSAST = true
				cfg.EnableSCA = true
				cfg.EnableSecrets = true
			}

			return runScan(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&configFile, "config", "c", ".broly.yaml", "Config file path")
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
	flags.BoolVar(&validateSecrets, "validate", false, "Validate detected secrets against source APIs")
	flags.BoolVar(&offline, "offline", false, "Run SCA in offline mode (skip OSV API)")
	flags.StringVar(&aiModel, "ai-model", "", "Together.ai model for AI features (default: Qwen/Qwen3-Coder-Next-FP8)")
	flags.BoolVar(&packageIntelligence, "package-intelligence", false, "Check packages against public registries to detect hallucinated dependencies")
	flags.StringVar(&packageRegistryMode, "package-registry-mode", "auto", "Package registry routing: auto, public-only, custom-only")
	flags.StringVar(&npmRegistryURL, "npm-registry-url", "", "Custom npm registry base URL for package intelligence")
	flags.StringVar(&pypiRegistryURL, "pypi-registry-url", "", "Custom PyPI registry base URL for package intelligence")
	flags.StringVar(&cratesRegistryURL, "crates-registry-url", "", "Custom crates registry base URL for package intelligence")
	flags.StringSliceVar(&languages, "languages", nil, "Limit SAST to specific languages (go,python,javascript)")
	flags.BoolVar(&aiFilterSecrets, "ai-filter-secrets", false, "Use AI to filter false positive secrets findings (requires TOGETHER_API_KEY)")
	flags.BoolVar(&aiSCAReachability, "ai-sca-reachability", false, "Use AI to analyze reachability of vulnerable dependencies (requires TOGETHER_API_KEY)")
	flags.BoolVar(&aiTriage, "ai-triage", false, "Use AI to triage findings: TRUE/FALSE positive verdict + fix suggestion (requires TOGETHER_API_KEY)")
	flags.BoolVar(&explain, "explain", false, "Add a plain-language attack scenario per finding (use with --ai-triage)")
	flags.BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	flags.StringVar(&baselineFile, "baseline", "", "Baseline file for suppress/require rules")
	flags.BoolVar(&incremental, "incremental", false, "Only re-scan SAST files changed since last run")
	flags.StringVar(&cachePath, "cache-path", "", "Path to incremental scan cache (default: .broly-cache.json)")
	flags.StringVar(&containerImage, "container", "", "Container image to scan (image:tag, path/to/image.tar)")
	flags.IntVar(&sastSliceFiles, "sast-slice-files", 0, "Max supporting files per SAST slice (default: 2)")

	return cmd
}

// loadConfigFile reads .broly.yaml (or the specified path) and returns a Config with those values.
// Missing file is silently ignored. Parse errors print a warning.
func loadConfigFile(path string) *core.Config {
	cfg := &core.Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse config file %s: %v\n", path, err)
	}
	return cfg
}

func runScan(cfg *core.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "broly v%s - scanning %s\n", version, strings.Join(cfg.Targets, ", "))
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
		if cfg.ContainerImage != "" {
			scanners = append(scanners, "container")
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
	if cfg.ContainerImage != "" {
		orch.Register(container.NewContainerScanner())
	}
	if len(cfg.AllowedLicenses) > 0 || len(cfg.DeniedLicenses) > 0 {
		orch.Register(license.NewLicenseScanner())
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
		w, err = os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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

	if len(result.Findings) > 0 || len(result.MissingRequired) > 0 {
		return errFindings
	}
	return nil
}

func sbomCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "sbom [paths...]",
		Short: "Generate a Software Bill of Materials",
		Long:  `Extract all packages from the specified paths and output a CycloneDX or SPDX SBOM.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"."}
			}

			result, err := sbom.Generate(cmd.Context(), args, version)
			if err != nil {
				return err
			}

			var w *os.File
			if outputFile != "" {
				w, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			switch outputFormat {
			case "cyclonedx", "cdx":
				return sbom.FormatCycloneDX(w, result)
			case "spdx":
				return sbom.FormatSPDX(w, result)
			default:
				return fmt.Errorf("unknown sbom format %q (use: cyclonedx, spdx)", outputFormat)
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "cyclonedx", "SBOM format: cyclonedx, spdx")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file (default: stdout)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(formatVersionInfo(currentVersionInfo()))
		},
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-rules",
		Short: "Validate that builtin secrets rules load successfully",
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := secrets.ValidateRules()
			if err != nil {
				return err
			}
			fmt.Printf("  %d builtin rules loaded successfully.\n", count)
			return nil
		},
	}
}
