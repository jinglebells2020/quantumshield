package store

import (
	"context"
	"quantumshield/pkg/models"
	"time"
)

// TrendPoint represents a data point in the scan trend.
type TrendPoint struct {
	ScanID           string    `json:"scan_id"`
	Timestamp        time.Time `json:"timestamp"`
	TotalFindings    int       `json:"total_findings"`
	CriticalCount    int       `json:"critical_count"`
	HighCount        int       `json:"high_count"`
	QuantumReadiness float64   `json:"quantum_readiness"`
	RiskScore        float64   `json:"risk_score"`
}

// Store defines the persistence interface.
type Store interface {
	Init(ctx context.Context) error
	Close() error
	SaveScan(ctx context.Context, result *models.ScanResult) error
	GetScan(ctx context.Context, scanID string) (*models.ScanResult, error)
	ListScans(ctx context.Context, limit int) ([]models.ScanResult, error)
	GetScanHistory(ctx context.Context) (*models.ScanHistory, error)
	GetTrend(ctx context.Context, days int) ([]TrendPoint, error)
}
