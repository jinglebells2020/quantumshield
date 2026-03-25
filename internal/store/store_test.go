package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"quantumshield/pkg/models"
)

// ---------- helpers ----------

func makeScan(id string, projectID string, startedAt time.Time, numFindings int) *models.ScanResult {
	completedAt := startedAt.Add(2 * time.Second)
	findings := make([]models.Finding, numFindings)
	critCount := 0
	highCount := 0
	for i := 0; i < numFindings; i++ {
		var sev models.Severity
		switch i % 4 {
		case 0:
			sev = models.SeverityCritical
			critCount++
		case 1:
			sev = models.SeverityHigh
			highCount++
		case 2:
			sev = models.SeverityMedium
		case 3:
			sev = models.SeverityLow
		}
		findings[i] = models.Finding{
			ID:               fmt.Sprintf("%s-f%d", id, i),
			ScanID:           id,
			RuleID:           fmt.Sprintf("rule-%d", i),
			Severity:         sev,
			Category:         models.CategoryAsymmetricEncryption,
			QuantumThreat:    models.ThreatBrokenByShor,
			FilePath:         fmt.Sprintf("src/crypto/file%d.go", i),
			LineStart:        10 + i,
			LineEnd:          15 + i,
			ColumnStart:      1,
			ColumnEnd:        40,
			CodeSnippet:      "rsa.GenerateKey(rand.Reader, 2048)",
			Algorithm:        "RSA-2048",
			KeySize:          2048,
			Usage:            "encryption",
			Library:          "crypto/rsa",
			Language:         "go",
			Description:      "RSA 2048-bit key vulnerable to Shor's algorithm",
			ReplacementAlgo:  "ML-KEM-768",
			MigrationEffort:  "medium",
			AutoFixAvailable: i%2 == 0,
			FixDiff:          "--- a/file.go\n+++ b/file.go",
			Confidence:       0.92,
			FalsePositive:    false,
			InDependency:     i%3 == 0,
			DependencyChain:  []string{"myapp", "libcrypto", "openssl"},
			ComplianceRefs: []models.ComplianceRef{
				{Framework: "NIST", Requirement: "SP 800-208", Status: "non-compliant"},
			},
			CreatedAt: completedAt,
		}
	}

	return &models.ScanResult{
		ID:        id,
		ProjectID: projectID,
		Config: models.ScanConfig{
			TargetPath:       "/src",
			Languages:        []string{"go", "python"},
			ScanConfigs:      true,
			ScanDependencies: true,
			ScanCertificates: false,
			ExcludePaths:     []string{"vendor/"},
			MinSeverity:      models.SeverityLow,
		},
		Status:   "completed",
		Findings: findings,
		Summary: models.ScanSummary{
			TotalFindings: numFindings,
			BySeverity: map[string]int{
				"CRITICAL": critCount,
				"HIGH":     highCount,
				"MEDIUM":   numFindings / 4,
				"LOW":      numFindings / 4,
			},
			ByCategory:       map[string]int{"Asymmetric Encryption": numFindings},
			ByLanguage:       map[string]int{"go": numFindings},
			ByThreatLevel:    map[string]int{"Shor": numFindings},
			QuantumReadiness: 0.35,
			RiskScore:        7.8,
		},
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		DurationMs:     2000,
		FilesScanned:   42,
		LinesScanned:   12000,
		RulesEvaluated: 87,
	}
}

// ---------- generic tests run against any Store ----------

func testSaveAndGet(t *testing.T, s Store) {
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	scan := makeScan("scan-001", "proj-a", now, 4)

	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	got, err := s.GetScan(ctx, "scan-001")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}

	// Verify top-level fields.
	if got.ID != scan.ID {
		t.Errorf("ID = %q, want %q", got.ID, scan.ID)
	}
	if got.ProjectID != scan.ProjectID {
		t.Errorf("ProjectID = %q, want %q", got.ProjectID, scan.ProjectID)
	}
	if got.Status != scan.Status {
		t.Errorf("Status = %q, want %q", got.Status, scan.Status)
	}
	if got.FilesScanned != scan.FilesScanned {
		t.Errorf("FilesScanned = %d, want %d", got.FilesScanned, scan.FilesScanned)
	}
	if got.LinesScanned != scan.LinesScanned {
		t.Errorf("LinesScanned = %d, want %d", got.LinesScanned, scan.LinesScanned)
	}
	if got.RulesEvaluated != scan.RulesEvaluated {
		t.Errorf("RulesEvaluated = %d, want %d", got.RulesEvaluated, scan.RulesEvaluated)
	}
	if got.DurationMs != scan.DurationMs {
		t.Errorf("DurationMs = %d, want %d", got.DurationMs, scan.DurationMs)
	}

	// Verify config roundtrip.
	if got.Config.TargetPath != scan.Config.TargetPath {
		t.Errorf("Config.TargetPath = %q, want %q", got.Config.TargetPath, scan.Config.TargetPath)
	}
	if len(got.Config.Languages) != len(scan.Config.Languages) {
		t.Errorf("Config.Languages len = %d, want %d", len(got.Config.Languages), len(scan.Config.Languages))
	}

	// Verify summary roundtrip.
	if got.Summary.TotalFindings != scan.Summary.TotalFindings {
		t.Errorf("Summary.TotalFindings = %d, want %d", got.Summary.TotalFindings, scan.Summary.TotalFindings)
	}
	if got.Summary.QuantumReadiness != scan.Summary.QuantumReadiness {
		t.Errorf("Summary.QuantumReadiness = %f, want %f", got.Summary.QuantumReadiness, scan.Summary.QuantumReadiness)
	}
	if got.Summary.RiskScore != scan.Summary.RiskScore {
		t.Errorf("Summary.RiskScore = %f, want %f", got.Summary.RiskScore, scan.Summary.RiskScore)
	}

	// Verify findings count and fields.
	if len(got.Findings) != len(scan.Findings) {
		t.Fatalf("Findings len = %d, want %d", len(got.Findings), len(scan.Findings))
	}

	// Find the first finding (they may be reordered by severity).
	var f0 *models.Finding
	for i := range got.Findings {
		if got.Findings[i].ID == scan.Findings[0].ID {
			f0 = &got.Findings[i]
			break
		}
	}
	if f0 == nil {
		t.Fatal("first finding not found in results")
	}

	if f0.RuleID != scan.Findings[0].RuleID {
		t.Errorf("Finding.RuleID = %q, want %q", f0.RuleID, scan.Findings[0].RuleID)
	}
	if f0.Severity != scan.Findings[0].Severity {
		t.Errorf("Finding.Severity = %d, want %d", f0.Severity, scan.Findings[0].Severity)
	}
	if f0.Category != scan.Findings[0].Category {
		t.Errorf("Finding.Category = %d, want %d", f0.Category, scan.Findings[0].Category)
	}
	if f0.QuantumThreat != scan.Findings[0].QuantumThreat {
		t.Errorf("Finding.QuantumThreat = %d, want %d", f0.QuantumThreat, scan.Findings[0].QuantumThreat)
	}
	if f0.Algorithm != scan.Findings[0].Algorithm {
		t.Errorf("Finding.Algorithm = %q, want %q", f0.Algorithm, scan.Findings[0].Algorithm)
	}
	if f0.KeySize != scan.Findings[0].KeySize {
		t.Errorf("Finding.KeySize = %d, want %d", f0.KeySize, scan.Findings[0].KeySize)
	}
	if f0.Confidence != scan.Findings[0].Confidence {
		t.Errorf("Finding.Confidence = %f, want %f", f0.Confidence, scan.Findings[0].Confidence)
	}
	if f0.AutoFixAvailable != scan.Findings[0].AutoFixAvailable {
		t.Errorf("Finding.AutoFixAvailable = %v, want %v", f0.AutoFixAvailable, scan.Findings[0].AutoFixAvailable)
	}
	if f0.InDependency != scan.Findings[0].InDependency {
		t.Errorf("Finding.InDependency = %v, want %v", f0.InDependency, scan.Findings[0].InDependency)
	}
	if len(f0.DependencyChain) != len(scan.Findings[0].DependencyChain) {
		t.Errorf("Finding.DependencyChain len = %d, want %d", len(f0.DependencyChain), len(scan.Findings[0].DependencyChain))
	}
	if len(f0.ComplianceRefs) != 1 {
		t.Fatalf("Finding.ComplianceRefs len = %d, want 1", len(f0.ComplianceRefs))
	}
	if f0.ComplianceRefs[0].Framework != "NIST" {
		t.Errorf("ComplianceRef.Framework = %q, want NIST", f0.ComplianceRefs[0].Framework)
	}

	// Verify timestamps roundtrip.
	if !timesEqual(got.StartedAt, scan.StartedAt) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, scan.StartedAt)
	}
	if !timesEqual(got.CompletedAt, scan.CompletedAt) {
		t.Errorf("CompletedAt = %v, want %v", got.CompletedAt, scan.CompletedAt)
	}
}

func testListScans(t *testing.T, s Store) {
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		scan := makeScan(
			fmt.Sprintf("scan-%03d", i),
			"proj-a",
			now.Add(time.Duration(i)*time.Minute),
			2,
		)
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatalf("SaveScan %d: %v", i, err)
		}
	}

	results, err := s.ListScans(ctx, 2)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("ListScans len = %d, want 2", len(results))
	}

	// Most recent first.
	if results[0].ID != "scan-002" {
		t.Errorf("first result ID = %q, want scan-002", results[0].ID)
	}
	if results[1].ID != "scan-001" {
		t.Errorf("second result ID = %q, want scan-001", results[1].ID)
	}

	// Findings should be empty (summary-only).
	for _, r := range results {
		if len(r.Findings) != 0 {
			t.Errorf("ListScans should not include findings, got %d", len(r.Findings))
		}
	}
}

func testGetTrend(t *testing.T, s Store) {
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)

	// Create scans across several days.
	days := []int{0, 1, 5, 10, 30}
	for i, d := range days {
		ts := now.AddDate(0, 0, -d)
		scan := makeScan(
			fmt.Sprintf("trend-%d", i),
			"proj-a",
			ts,
			(i+1)*2,
		)
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatalf("SaveScan %d: %v", i, err)
		}
	}

	// Last 7 days should include day 0, 1, 5.
	points, err := s.GetTrend(ctx, 7)
	if err != nil {
		t.Fatalf("GetTrend: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("GetTrend(7) len = %d, want 3", len(points))
	}

	// Points should be ordered by timestamp ascending.
	for i := 1; i < len(points); i++ {
		if points[i].Timestamp.Before(points[i-1].Timestamp) {
			t.Errorf("trend points not in ascending order at index %d", i)
		}
	}

	// Verify first point has correct total findings.
	if points[0].TotalFindings != 6 { // scan at day -5 has (2+1)*2=6 findings
		t.Errorf("first trend point TotalFindings = %d, want 6", points[0].TotalFindings)
	}

	// Last 31 days should include all 5.
	allPoints, err := s.GetTrend(ctx, 31)
	if err != nil {
		t.Fatalf("GetTrend(31): %v", err)
	}
	if len(allPoints) != 5 {
		t.Errorf("GetTrend(31) len = %d, want 5", len(allPoints))
	}
}

func testGetScanHistory(t *testing.T, s Store) {
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		scan := makeScan(
			fmt.Sprintf("hist-%d", i),
			"proj-history",
			now.Add(time.Duration(i)*time.Hour),
			i+1,
		)
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatalf("SaveScan %d: %v", i, err)
		}
	}

	history, err := s.GetScanHistory(ctx)
	if err != nil {
		t.Fatalf("GetScanHistory: %v", err)
	}

	if history.ProjectID != "proj-history" {
		t.Errorf("ProjectID = %q, want proj-history", history.ProjectID)
	}
	if len(history.Scans) != 3 {
		t.Fatalf("Scans len = %d, want 3", len(history.Scans))
	}

	// Ordered by StartedAt ascending.
	for i := 1; i < len(history.Scans); i++ {
		if history.Scans[i].StartedAt.Before(history.Scans[i-1].StartedAt) {
			t.Errorf("history scans not in ascending order at index %d", i)
		}
	}
}

// timesEqual compares two times at second precision (SQLite stores at second precision).
func timesEqual(a, b time.Time) bool {
	return a.UTC().Truncate(time.Second).Equal(b.UTC().Truncate(time.Second))
}

// ---------- SQLite tests ----------

func TestSQLiteStore_SaveAndGet(t *testing.T) {
	testSaveAndGet(t, NewSQLiteStore(":memory:"))
}

func TestSQLiteStore_ListScans(t *testing.T) {
	testListScans(t, NewSQLiteStore(":memory:"))
}

func TestSQLiteStore_GetTrend(t *testing.T) {
	testGetTrend(t, NewSQLiteStore(":memory:"))
}

func TestSQLiteStore_GetScanHistory(t *testing.T) {
	testGetScanHistory(t, NewSQLiteStore(":memory:"))
}

// ---------- Memory tests ----------

func TestMemoryStore_SaveAndGet(t *testing.T) {
	testSaveAndGet(t, NewMemoryStore())
}

func TestMemoryStore_ListScans(t *testing.T) {
	testListScans(t, NewMemoryStore())
}

func TestMemoryStore_GetTrend(t *testing.T) {
	testGetTrend(t, NewMemoryStore())
}

func TestMemoryStore_GetScanHistory(t *testing.T) {
	testGetScanHistory(t, NewMemoryStore())
}
