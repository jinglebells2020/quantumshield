package models

type MigrationPath struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Hybrid   string `json:"hybrid,omitempty"`
	Effort   string `json:"effort"`
	Priority string `json:"priority"`
}

type MigrationPlan struct {
	ID        string           `json:"id"`
	ProjectID string           `json:"project_id"`
	ScanID    string           `json:"scan_id"`
	Status    string           `json:"status"`
	Phases    []MigrationPhase `json:"phases"`
	EstHours  int              `json:"estimated_hours"`
}

type MigrationPhase struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Items       []MigrationItem `json:"items"`
	Progress    float64         `json:"progress"`
}

type MigrationItem struct {
	FindingID   string `json:"finding_id"`
	Algorithm   string `json:"algorithm"`
	Replacement string `json:"replacement"`
	FilePath    string `json:"file_path"`
	Effort      string `json:"effort"`
	AutoFix     bool   `json:"auto_fix"`
	Status      string `json:"status"`
}
