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

	Offline      bool     `yaml:"offline" json:"offline"`
	Languages    []string `yaml:"languages" json:"languages"`
	AIModel      string   `yaml:"ai_model" json:"ai_model"`
	AIFilterSecrets   bool `yaml:"ai_filter_secrets" json:"ai_filter_secrets"`
	AISCAReachability bool `yaml:"ai_sca_reachability" json:"ai_sca_reachability"`
	AITriage          bool `yaml:"ai_triage" json:"ai_triage"`
	Explain           bool `yaml:"explain" json:"explain"`
	BaselineFile string `yaml:"baseline_file" json:"baseline_file"`
	Incremental  bool   `yaml:"incremental" json:"incremental"`
	CachePath    string `yaml:"cache_path" json:"cache_path"`
	Quiet          bool   `yaml:"quiet" json:"quiet"`
	ContainerImage string `yaml:"container_image" json:"container_image"`
}
