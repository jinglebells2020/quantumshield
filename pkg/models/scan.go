package models

import "time"

type ScanConfig struct {
	TargetPath       string   `json:"target_path"`
	Languages        []string `json:"languages,omitempty"`
	ScanConfigs      bool     `json:"scan_configs"`
	ScanDependencies bool     `json:"scan_dependencies"`
	ScanCertificates bool     `json:"scan_certificates"`
	ExcludePaths     []string `json:"exclude_paths,omitempty"`
	CustomRulesPath  string   `json:"custom_rules_path,omitempty"`
	MinSeverity      Severity `json:"min_severity"`
}

type ScanResult struct {
	ID             string      `json:"id"`
	OrgID          string      `json:"org_id,omitempty"`
	ProjectID      string      `json:"project_id,omitempty"`
	Config         ScanConfig  `json:"config"`
	Status         string      `json:"status"`
	Findings       []Finding   `json:"findings"`
	Summary        ScanSummary `json:"summary"`
	StartedAt      time.Time   `json:"started_at"`
	CompletedAt    time.Time   `json:"completed_at"`
	DurationMs     int64       `json:"duration_ms"`
	FilesScanned   int         `json:"files_scanned"`
	LinesScanned   int         `json:"lines_scanned"`
	RulesEvaluated int         `json:"rules_evaluated"`
}

type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByCategory       map[string]int `json:"by_category"`
	ByLanguage       map[string]int `json:"by_language"`
	ByThreatLevel    map[string]int `json:"by_threat_level"`
	QuantumReadiness float64        `json:"quantum_readiness"`
	RiskScore        float64        `json:"risk_score"`
}
