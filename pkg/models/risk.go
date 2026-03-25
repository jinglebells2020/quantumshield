package models

type RiskAssessment struct {
	OverallScore      float64           `json:"overall_score"`
	QuantumReadiness  float64           `json:"quantum_readiness"`
	Breakdown         RiskBreakdown     `json:"breakdown"`
	HNDLRisk          HNDLAssessment    `json:"hndl_risk"`
	MigrationEstimate MigrationEstimate `json:"migration_estimate"`
	ComplianceGaps    []ComplianceGap   `json:"compliance_gaps"`
	Recommendations   []Recommendation  `json:"recommendations"`
}

type RiskBreakdown struct {
	CryptographicRisk float64 `json:"cryptographic_risk"`
	ExposureRisk      float64 `json:"exposure_risk"`
	DependencyRisk    float64 `json:"dependency_risk"`
	ComplianceRisk    float64 `json:"compliance_risk"`
}

type HNDLAssessment struct {
	HighRiskAssets     int    `json:"high_risk_assets"`
	DataRetentionYears int    `json:"data_retention_years"`
	EstimatedThreatYear int   `json:"estimated_threat_year"`
	TimeToMigrate      string `json:"time_to_migrate"`
	Urgency            string `json:"urgency"`
}

type MigrationEstimate struct {
	AutoFixable    int    `json:"auto_fixable"`
	ManualFix      int    `json:"manual_fix"`
	DependencyFix  int    `json:"dependency_fix"`
	TotalFindings  int    `json:"total_findings"`
	EstimatedHours string `json:"estimated_hours"`
}

type ComplianceGap struct {
	Framework   string  `json:"framework"`
	Compliant   float64 `json:"compliant_pct"`
	Gaps        int     `json:"gaps"`
	Description string  `json:"description"`
}

type Recommendation struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Effort      string `json:"effort"`
	Impact      string `json:"impact"`
}
