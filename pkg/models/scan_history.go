package models

// ScanHistory contains historical scan data for a project, ordered chronologically.
type ScanHistory struct {
	ProjectID string       `json:"project_id"`
	Scans     []ScanResult `json:"scans"`
}
