package models

import "time"

// CryptoCommit represents a developer commit with crypto-related changes.
type CryptoCommit struct {
	SHA             string    `json:"sha"`
	Author          string    `json:"author"`
	Timestamp       time.Time `json:"timestamp"`
	FilesChanged    []string  `json:"files_changed"`
	FindingsAdded   []Finding `json:"findings_added"`
	FindingsRemoved []Finding `json:"findings_removed"`
	CryptoAction    string    `json:"crypto_action"`
}
