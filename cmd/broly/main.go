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

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/container"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/iac"
	"github.com/Shasheen8/Broly/pkg/license"
	"github.com/Shasheen8/Broly/pkg/orchestrator"
	"github.com/Shasheen8/Broly/pkg/report"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sbom"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/secrets"
	"github.com/Shasheen8/Broly/pkg/vulnclass"
	"github.com/Shasheen8/Broly/pkg/workflow"
)

var (
	version = "dev"
	commit  = "none"

	errFindingsDetected           = errors.New("findings detected")
	errMissingRequiredFindings    = errors.New("required baseline findings missing")
	errFindingsAndMissingRequired = errors.New("findings detected and required baseline findings missing")
)

func main() {
	root := &cobra.Command{
		Use:   "broly",
		Short: "Broly - Berserker Vulnerability Scanner",
		Long: `Broly is a CLI-first berserker code security scanner.

SCANNERS
  secrets        487 Titus rules, Hyperscan locally (Go regex in CI)
  sca            osv-scalibr + osv.dev, 20 ecosystems
  sast           Together AI LLM, 17 regex prefilter patterns
  workflow       zizmor for GitHub Actions static analysis
  iac            checkov for Terraform, Kubernetes, Helm, CloudFormation
  supply-chain   depx for known-malicious package detection
  container      go-containerregistry + osv.dev
  license        File-based detection, 13 license types
  sbom           CycloneDX 1.5 or SPDX 2.3

AI FEATURES (require TOGETHER_API_KEY)
  --ai-triage              Verdict (TP/FP) + fix suggestion per finding
  --ai-triage --explain    + attack scenario per finding
  --adversarial            Adversarial verify on critical SAST TPs
  --exploit-chains         Link cross-scanner TPs into attack narratives
  --ai-filter-secrets      Filter secrets false positives with AI
  --ai-sca-reachability    Check if vulnerable deps are actually called
  --package-intelligence   Detect hallucinated/non-existent packages

QUICK START
  broly scan                              # secrets + SCA + SAST
  broly scan . --sast --ai-triage         # SAST with AI triage
  broly scan . --workflow --iac          # IaC + workflow scanning
  broly scan . --ai-triage --adversarial  # Full adversarial pipeline
  broly sbom                              # Generate CycloneDX SBOM
  broly update                            # Update to latest version

Built in Go for speed. Designed for local developer runs and CI.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(sbomCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(updateCmd())

	if err := root.Execute(); err != nil {
		if lines := completionMessage(err); len(lines) > 0 {
			fmt.Fprintln(os.Stderr)
			for _, line := range lines {
				fmt.Fprintln(os.Stderr, line)
			}
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
		enableWorkflow      bool
		enableIaC           bool
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
		adversarial         bool
		exploitChains       bool
		supplyChain         bool
		explain             bool
		baselineFile        string
		incremental         bool
		cachePath           string
		containerImage      string
		autoContainers      bool
		sastSliceFiles      int
	)

	// vulnClassFlags holds one bool flag per registered vulnerability class
	// (e.g. --idor, --xss), keyed by class name.
	vulnClassFlags := make(map[string]*bool, len(vulnclass.All))

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan targets for security findings",
		Long: `Run Broly's scan engines against the specified paths.
By default secrets, SCA, and SAST are enabled and the current directory is scanned.

SCANNERS
  --secrets              Enable secrets scanning
  --sca                  Enable SCA scanning
  --sast                 Enable SAST scanning (requires TOGETHER_API_KEY)
  --workflow             Enable GitHub Actions workflow scanning (requires zizmor)
  --iac                  Enable IaC scanning: Terraform, K8s, Helm, CloudFormation (requires checkov)
  --supply-chain         Audit deps against known-malicious package feeds (requires depx)
  --container <image>    Scan a container image (image:tag, path/to/image.tar)
  --auto-containers      Auto-discover and scan Dockerfile base images

AI ENHANCEMENTS (require TOGETHER_API_KEY)
  --ai-triage            Verdict (TP/FP) + fix suggestion per finding
  --explain              Add a plain-language attack scenario per finding
  --adversarial          Adversarial verify on critical SAST TPs (requires --ai-triage)
  --exploit-chains       Synthesize exploit chains linking cross-scanner TPs (requires --ai-triage)
  --ai-filter-secrets    Filter secrets false positives with AI
  --ai-sca-reachability  Check if vulnerable deps are actually called
  --package-intelligence Detect hallucinated/non-existent packages

` + vulnClassHelpSection() + `
OUTPUT
  -f, --format <fmt>     Output format: table, json, sarif (default: table)
  -o, --output <file>    Write output to file (default: stdout)
  --min-severity <sev>   Minimum severity: info, low, medium, high, critical

FILTERING & SUPPRESSION
  --exclude <paths>       Paths to exclude from scanning
  --languages <langs>     Limit SAST to specific languages (go,python,javascript)
  --baseline <file>       Baseline file for suppress/require rules
  --incremental           Only re-scan SAST files changed since last run
  --config <file>         Config file path (default: .broly.yaml)

OTHER
  --workers <n>           Number of parallel workers (default: 8)
  --no-redact             Disable secret redaction in output
  --offline               Run SCA in offline mode (skip OSV API)
  -q, --quiet             Suppress progress output
  --sast-slice-files <n>  Max supporting files per SAST slice (default: 2)`,
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
			if f.Changed("adversarial") {
				cfg.Adversarial = adversarial
			}
			if f.Changed("exploit-chains") {
				cfg.ExploitChains = exploitChains
			}
			if f.Changed("supply-chain") {
				cfg.SupplyChain = supplyChain
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
			if f.Changed("auto-containers") {
				cfg.AutoContainers = autoContainers
			}
			if f.Changed("sast-slice-files") {
				cfg.SASTSliceFiles = sastSliceFiles
			}

			// Vuln-class focus flags (e.g. --idor, --xss) override config file.
			var requestedClasses []string
			for _, vc := range vulnclass.All {
				if *vulnClassFlags[vc.Name] {
					requestedClasses = append(requestedClasses, vc.Name)
				}
			}
			if len(requestedClasses) > 0 {
				cfg.VulnClasses = requestedClasses
			}
			if f.Changed("workflow") {
				cfg.EnableWorkflow = enableWorkflow
			}
			if f.Changed("iac") {
				cfg.EnableIaC = enableIaC
			}

			if cfg.Adversarial && !cfg.AITriage {
				return fmt.Errorf("--adversarial requires --ai-triage")
			}
			if cfg.ExploitChains && !cfg.AITriage {
				return fmt.Errorf("--exploit-chains requires --ai-triage")
			}

			finalizeScannerSelection(
				cfg,
				f.Changed("sast"), enableSAST,
				f.Changed("sca"), enableSCA,
				f.Changed("secrets"), enableSecrets,
			)

			return runScan(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&configFile, "config", "c", ".broly.yaml", "Config file path")
	flags.StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, sarif")
	flags.StringVarP(&outputFile, "output", "o", "", "Write output to file (default: stdout)")
	flags.BoolVar(&enableSAST, "sast", false, "Enable SAST scanning")
	flags.BoolVar(&enableSCA, "sca", false, "Enable SCA scanning")
	flags.BoolVar(&enableSecrets, "secrets", false, "Enable secrets scanning")
	flags.BoolVar(&enableWorkflow, "workflow", false, "Enable GitHub Actions workflow scanning (requires zizmor)")
	flags.BoolVar(&enableIaC, "iac", false, "Enable IaC scanning: Terraform, Kubernetes, Helm, CloudFormation (requires checkov)")
	flags.IntVar(&workers, "workers", 8, "Number of parallel workers")
	flags.StringVar(&minSeverity, "min-severity", "info", "Minimum severity: info, low, medium, high, critical")
	flags.StringSliceVar(&excludePaths, "exclude", nil, "Paths to exclude from scanning")
	flags.StringVar(&secretsRules, "secrets-rules", "", "Custom secrets rules directory")
	flags.BoolVar(&disableRedact, "no-redact", false, "Disable secret redaction in human-readable output")
	flags.BoolVar(&validateSecrets, "validate", false, "Validate detected secrets against source APIs")
	flags.BoolVar(&offline, "offline", false, "Run SCA in offline mode (skip OSV API)")
	flags.StringVar(&aiModel, "ai-model", "", fmt.Sprintf("Together.ai model for AI features (default: %s)", ai.DefaultModel))
	flags.BoolVar(&packageIntelligence, "package-intelligence", false, "Check packages against public registries to detect hallucinated dependencies")
	flags.StringVar(&packageRegistryMode, "package-registry-mode", "auto", "Package registry routing: auto, public-only, custom-only")
	flags.StringVar(&npmRegistryURL, "npm-registry-url", "", "Custom npm registry base URL for package intelligence")
	flags.StringVar(&pypiRegistryURL, "pypi-registry-url", "", "Custom PyPI registry base URL for package intelligence")
	flags.StringVar(&cratesRegistryURL, "crates-registry-url", "", "Custom crates registry base URL for package intelligence")
	flags.StringSliceVar(&languages, "languages", nil, "Limit SAST to specific languages (go,python,javascript)")
	flags.BoolVar(&aiFilterSecrets, "ai-filter-secrets", false, "Use AI to filter false positive secrets findings (requires TOGETHER_API_KEY)")
	flags.BoolVar(&aiSCAReachability, "ai-sca-reachability", false, "Use AI to analyze reachability of vulnerable dependencies (requires TOGETHER_API_KEY)")
	flags.BoolVar(&aiTriage, "ai-triage", false, "Use AI to triage findings: TRUE/FALSE positive verdict + fix suggestion (requires TOGETHER_API_KEY)")
	flags.BoolVar(&adversarial, "adversarial", false, "Run adversarial verification on critical SAST true positives (requires --ai-triage)")
	flags.BoolVar(&exploitChains, "exploit-chains", false, "Synthesize exploit chains linking cross-scanner true positives (requires --ai-triage)")
	flags.BoolVar(&supplyChain, "supply-chain", false, "Audit dependencies against known-malicious package feeds (requires depx)")
	flags.BoolVar(&explain, "explain", false, "Add a plain-language attack scenario per finding (use with --ai-triage)")
	flags.BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output while keeping warnings visible")
	flags.StringVar(&baselineFile, "baseline", "", "Baseline file for suppress/require rules")
	flags.BoolVar(&incremental, "incremental", false, "Only re-scan SAST files changed since last run")
	flags.StringVar(&cachePath, "cache-path", "", "Path to incremental scan cache (default: .broly-cache.json)")
	flags.StringVar(&containerImage, "container", "", "Container image to scan (image:tag, path/to/image.tar)")
	flags.BoolVar(&autoContainers, "auto-containers", false, "Auto-discover and scan Dockerfile base images")
	flags.IntVar(&sastSliceFiles, "sast-slice-files", 0, "Max supporting files per SAST slice (default: 2)")

	for _, vc := range vulnclass.All {
		vulnClassFlags[vc.Name] = flags.Bool(vc.Flag, false,
			fmt.Sprintf("Focus scan on %s (%s)", vc.Title, strings.Join(vc.CWEs, ", ")))
	}

	return cmd
}

// vulnClassHelpSection renders the VULN CLASS FOCUS help section from the
// vulnclass registry so the help text can never drift from the registered
// classes and their CWE lists.
func vulnClassHelpSection() string {
	var sb strings.Builder
	sb.WriteString("VULN CLASS FOCUS (showcase specific vulnerability detection)\n")
	for _, vc := range vulnclass.All {
		fmt.Fprintf(&sb, "  --%-21s %s (%s)\n", vc.Flag, vc.Title, strings.Join(vc.CWEs, "/"))
	}
	return sb.String()
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
		core.Warnf("could not parse config file %s: %v", path, err)
	}
	return cfg
}

func finalizeScannerSelection(cfg *core.Config, cliSAST, enableSAST, cliSCA, enableSCA, cliSecrets, enableSecrets bool) {
	if cliSAST {
		cfg.EnableSAST = enableSAST
	}
	if cliSCA {
		cfg.EnableSCA = enableSCA
	}
	if cliSecrets {
		cfg.EnableSecrets = enableSecrets
	}

	if !cfg.EnableSAST && !cfg.EnableSCA && !cfg.EnableSecrets && !cfg.EnableWorkflow && !cfg.EnableIaC && cfg.ContainerImage == "" && !cfg.AutoContainers && !cfg.SupplyChain {
		cfg.EnableSAST = true
		cfg.EnableSCA = true
		cfg.EnableSecrets = true
	}
}

func runScan(cfg *core.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if !cfg.Quiet {
		printBanner()
		fmt.Fprintf(os.Stderr, "  scanning %s\n", strings.Join(cfg.Targets, ", "))
		fmt.Fprintf(os.Stderr, "  scanners: %s | workers: %d\n", strings.Join(configuredScannerNames(cfg), ", "), cfg.Workers)
		for _, line := range vulnclass.InfoLines(cfg.VulnClasses) {
			fmt.Fprintln(os.Stderr, line)
		}
		fmt.Fprintln(os.Stderr)
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
	if cfg.EnableWorkflow {
		orch.Register(workflow.NewWorkflowScanner())
	}
	if cfg.EnableIaC {
		orch.Register(iac.NewIaCScanner())
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

	// Auto-scan Dockerfile base images, skipping any explicit --container.
	scanned := map[string]bool{}
	if cfg.ContainerImage != "" {
		scanned[cfg.ContainerImage] = true
	}
	if cfg.AutoContainers {
		for _, target := range cfg.Targets {
			info, err := os.Stat(target)
			if err != nil || !info.IsDir() {
				continue
			}
			for _, rel := range container.FindContainerSpecs(target) {
				content, ok := container.ReadDockerfile(target, rel)
				if !ok {
					continue
				}
				for _, img := range container.ImagesFromFile(rel, content) {
					if scanned[img] {
						continue
					}
					scanned[img] = true
					cr, err := scanContainerImage(ctx, cfg, img, rel)
					if err != nil {
						core.Warnf("container scan of %s failed: %v", img, err)
						continue
					}
					result.Findings = append(result.Findings, cr.Findings...)
				}
			}
		}
	}
	result.Metrics.FindingsCount = len(result.Findings)
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

	return scanCompletionError(result)
}

func scanContainerImage(ctx context.Context, base *core.Config, image, dockerfile string) (*core.ScanResult, error) {
	cfg := *base
	cfg.ContainerImage = image
	orch := orchestrator.New(&cfg)
	orch.Register(container.NewContainerScanner())
	res, err := orch.Run(ctx)
	if err != nil {
		return nil, err
	}
	for i := range res.Findings {
		res.Findings[i].FilePath = dockerfile
		res.Findings[i].ComputeIdentityKeys()
	}
	return res, nil
}

func sbomCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "sbom [paths...]",
		Short: "Generate a Software Bill of Materials",
		Long:  `Extract packages from the specified paths and output a CycloneDX or SPDX SBOM.`,
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
				return fmt.Errorf("unknown sbom format %q (use: cyclonedx, cdx, spdx)", outputFormat)
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "cyclonedx", "SBOM format: cyclonedx, cdx, spdx")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file (default: stdout)")
	return cmd
}

func versionCmd() *cobra.Command {
	var short bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			info := currentVersionInfo()
			if short {
				fmt.Println(info.Version)
				return
			}
			fmt.Println(formatVersionInfo(info))
		},
	}
	cmd.Flags().BoolVar(&short, "short", false, "Print only the version string")
	return cmd
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-rules",
		Short: "Validate that built-in secrets rules load successfully",
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := secrets.ValidateRules()
			if err != nil {
				return err
			}
			fmt.Printf("  Validated %d built-in secrets rules.\n", count)
			return nil
		},
	}
}

func configuredScannerNames(cfg *core.Config) []string {
	scanners := make([]string, 0, 6)
	if cfg.EnableSecrets {
		scanners = append(scanners, "secrets")
	}
	if cfg.EnableSCA {
		scanners = append(scanners, "sca")
	}
	if cfg.EnableSAST {
		scanners = append(scanners, "sast")
	}
	if cfg.EnableWorkflow {
		scanners = append(scanners, "workflow")
	}
	if cfg.EnableIaC {
		scanners = append(scanners, "iac")
	}
	if cfg.SupplyChain {
		scanners = append(scanners, "supply-chain")
	}
	if cfg.ContainerImage != "" || cfg.AutoContainers {
		scanners = append(scanners, "containers")
	}
	if len(cfg.AllowedLicenses) > 0 || len(cfg.DeniedLicenses) > 0 {
		scanners = append(scanners, "license")
	}
	return scanners
}

func printBanner() {
	info := currentVersionInfo()
	ver := info.Version
	if ver == "" || ver == "dev" {
		ver = "dev"
	}
	banner := fmt.Sprintf(`
 ____  ____   ___  _  __   __
| __ )|  _ \ / _ \| | \ \ / /
|  _ \| |_) | | | | |  \ V / 
| |_) |  _ <| |_| | |___| |  
|____/|_| \_\\___/|_____|_|  

  Berserker Vulnerability Scanner %s
  Secrets - SCA - SAST - Workflow - IaC - Supply Chain
  Powered by Together AI (%s)
`, ver, ai.DefaultModel)
	fmt.Fprint(os.Stderr, banner)
}

func scanCompletionError(result *core.ScanResult) error {
	hasFindings := len(result.Findings) > 0
	hasMissingRequired := len(result.MissingRequired) > 0

	switch {
	case hasFindings && hasMissingRequired:
		return errFindingsAndMissingRequired
	case hasFindings:
		return errFindingsDetected
	case hasMissingRequired:
		return errMissingRequiredFindings
	default:
		return nil
	}
}

func completionMessage(err error) []string {
	switch {
	case errors.Is(err, errFindingsAndMissingRequired):
		return []string{
			"Scan completed with findings, and required baseline matches were missing. Broly is exiting with code 1 so shells and CI can detect the result.",
			"Tip: use --format json or --format sarif for machine-readable findings, then review the missing required items in the summary above.",
		}
	case errors.Is(err, errFindingsDetected):
		return []string{
			"Scan completed with findings. Broly is exiting with code 1 so shells and CI can detect the result.",
			"Tip: use --format json or --format sarif for machine-readable output.",
		}
	case errors.Is(err, errMissingRequiredFindings):
		return []string{
			"Scan completed without findings, but required baseline matches were missing. Broly is exiting with code 1 so shells and CI can detect the result.",
			"Tip: review the missing required items in the summary above.",
		}
	default:
		return nil
	}
}
