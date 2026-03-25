package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"quantumshield/pkg/models"
)

// MemoryStore is an in-memory implementation of the Store interface.
type MemoryStore struct {
	scans []models.ScanResult
	mu    sync.RWMutex
}

// NewMemoryStore creates a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Init is a no-op for the in-memory store.
func (m *MemoryStore) Init(ctx context.Context) error {
	return nil
}

// Close is a no-op for the in-memory store.
func (m *MemoryStore) Close() error {
	return nil
}

// SaveScan appends a scan result to the in-memory slice.
// If a scan with the same ID exists, it is replaced.
func (m *MemoryStore) SaveScan(ctx context.Context, result *models.ScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.scans {
		if existing.ID == result.ID {
			m.scans[i] = *result
			return nil
		}
	}
	m.scans = append(m.scans, *result)
	return nil
}

// GetScan retrieves a scan by ID.
func (m *MemoryStore) GetScan(ctx context.Context, scanID string) (*models.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.scans {
		if s.ID == scanID {
			cpy := s
			return &cpy, nil
		}
	}
	return nil, fmt.Errorf("scan not found")
}

// ListScans returns up to `limit` scans ordered by CompletedAt descending.
func (m *MemoryStore) ListScans(ctx context.Context, limit int) ([]models.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	// Make a copy and sort by CompletedAt descending.
	sorted := make([]models.ScanResult, len(m.scans))
	copy(sorted, m.scans)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CompletedAt.After(sorted[j].CompletedAt)
	})

	if limit > len(sorted) {
		limit = len(sorted)
	}

	// Return summaries only (strip findings for performance parity with SQLite).
	result := make([]models.ScanResult, limit)
	for i := 0; i < limit; i++ {
		r := sorted[i]
		r.Findings = nil
		result[i] = r
	}
	return result, nil
}

// GetScanHistory returns all scans ordered by StartedAt ascending.
func (m *MemoryStore) GetScanHistory(ctx context.Context) (*models.ScanHistory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sorted := make([]models.ScanResult, len(m.scans))
	copy(sorted, m.scans)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].StartedAt.Before(sorted[j].StartedAt)
	})

	history := &models.ScanHistory{
		Scans: sorted,
	}
	if len(sorted) > 0 {
		history.ProjectID = sorted[0].ProjectID
	}
	return history, nil
}

// GetTrend returns trend data points from the last N days.
func (m *MemoryStore) GetTrend(ctx context.Context, days int) ([]TrendPoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -days)

	// Collect matching scans sorted by CompletedAt ascending.
	var matching []models.ScanResult
	for _, s := range m.scans {
		if !s.CompletedAt.Before(cutoff) {
			matching = append(matching, s)
		}
	}
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].CompletedAt.Before(matching[j].CompletedAt)
	})

	var points []TrendPoint
	for _, s := range matching {
		criticalCount := s.Summary.BySeverity["CRITICAL"]
		highCount := s.Summary.BySeverity["HIGH"]

		points = append(points, TrendPoint{
			ScanID:           s.ID,
			Timestamp:        s.CompletedAt,
			TotalFindings:    s.Summary.TotalFindings,
			CriticalCount:    criticalCount,
			HighCount:        highCount,
			QuantumReadiness: s.Summary.QuantumReadiness,
			RiskScore:        s.Summary.RiskScore,
		})
	}
	return points, nil
}
