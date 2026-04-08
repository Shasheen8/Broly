package core

type Config struct {
	Targets       []string `yaml:"targets" json:"targets"`
	EnableSAST    bool     `yaml:"enable_sast" json:"enable_sast"`
	EnableSCA     bool     `yaml:"enable_sca" json:"enable_sca"`
	EnableSecrets bool     `yaml:"enable_secrets" json:"enable_secrets"`

	Workers     int   `yaml:"workers" json:"workers"`
	MaxFileSize int64 `yaml:"max_file_size" json:"max_file_size"`

	OutputFormat string `yaml:"output_format" json:"output_format"`
	OutputFile   string `yaml:"output_file" json:"output_file"`

	MinSeverity    Severity `yaml:"min_severity" json:"min_severity"`
	ExcludePaths   []string `yaml:"exclude_paths" json:"exclude_paths"`
	IncludeRuleIDs []string `yaml:"include_rule_ids" json:"include_rule_ids"`
	ExcludeRuleIDs []string `yaml:"exclude_rule_ids" json:"exclude_rule_ids"`

	SecretsRulesDir  string `yaml:"secrets_rules_dir" json:"secrets_rules_dir"`
	DisableRedaction bool   `yaml:"disable_redaction" json:"disable_redaction"`
	ValidateSecrets  bool   `yaml:"validate_secrets" json:"validate_secrets"`

	Offline             bool     `yaml:"offline" json:"offline"`
	Languages           []string `yaml:"languages" json:"languages"`
	AIModel             string   `yaml:"ai_model" json:"ai_model"`
	PackageIntelligence bool     `yaml:"package_intelligence" json:"package_intelligence"`
	PackageRegistryMode string   `yaml:"package_registry_mode" json:"package_registry_mode"`
	NPMRegistryURL      string   `yaml:"npm_registry_url" json:"npm_registry_url"`
	PyPIRegistryURL     string   `yaml:"pypi_registry_url" json:"pypi_registry_url"`
	CratesRegistryURL   string   `yaml:"crates_registry_url" json:"crates_registry_url"`
	AIFilterSecrets     bool     `yaml:"ai_filter_secrets" json:"ai_filter_secrets"`
	AISCAReachability   bool     `yaml:"ai_sca_reachability" json:"ai_sca_reachability"`
	AITriage            bool     `yaml:"ai_triage" json:"ai_triage"`
	Explain             bool     `yaml:"explain" json:"explain"`
	BaselineFile        string   `yaml:"baseline_file" json:"baseline_file"`
	Incremental         bool     `yaml:"incremental" json:"incremental"`
	CachePath           string   `yaml:"cache_path" json:"cache_path"`
	Quiet               bool     `yaml:"quiet" json:"quiet"`
	ContainerImage      string   `yaml:"container_image" json:"container_image"`
	SASTSliceFiles      int      `yaml:"sast_slice_files" json:"sast_slice_files"`
	AllowedLicenses     []string `yaml:"allowed_licenses" json:"allowed_licenses"`
	DeniedLicenses      []string `yaml:"denied_licenses" json:"denied_licenses"`
}
