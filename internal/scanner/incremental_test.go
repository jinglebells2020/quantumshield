package scanner

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestBaselineStore_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	bs := NewBaselineStore(dir)
	baseline := &Baseline{
		ScanID: "scan-001",
		Branch: "main",
		Findings: []models.Finding{
			{ID: "f-1", Algorithm: "RSA-2048", FilePath: "test.go", LineStart: 10, RuleID: "QS-RSA-001"},
		},
	}
	if err := bs.Save(baseline); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := bs.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded baseline is nil")
	}
	if loaded.ScanID != "scan-001" {
		t.Errorf("scan ID: got %s, want scan-001", loaded.ScanID)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("findings: got %d, want 1", len(loaded.Findings))
	}
}

func TestBaselineStore_LoadMissing(t *testing.T) {
	bs := NewBaselineStore(t.TempDir())
	loaded, err := bs.Load()
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil for missing baseline")
	}
}

func TestComputeDiff(t *testing.T) {
	baseline := &Baseline{
		ScanID: "old",
		Findings: []models.Finding{
			{ID: "f-1", Algorithm: "RSA-2048", FilePath: "a.go", LineStart: 10, RuleID: "QS-RSA-001"},
			{ID: "f-2", Algorithm: "MD5", FilePath: "b.go", LineStart: 20, RuleID: "QS-MD5-001"},
		},
	}
	current := []models.Finding{
		{ID: "f-1", Algorithm: "RSA-2048", FilePath: "a.go", LineStart: 10, RuleID: "QS-RSA-001"},
		{ID: "f-3", Algorithm: "SHA-1", FilePath: "c.go", LineStart: 30, RuleID: "QS-SHA1-001"},
	}
	diff := ComputeDiff(baseline, current)
	if diff.NewCount != 1 {
		t.Errorf("new: got %d, want 1", diff.NewCount)
	}
	if diff.FixedCount != 1 {
		t.Errorf("fixed: got %d, want 1", diff.FixedCount)
	}
	if diff.NewFindings[0].Algorithm != "SHA-1" {
		t.Errorf("new should be SHA-1")
	}
	if diff.FixedFindings[0].Algorithm != "MD5" {
		t.Errorf("fixed should be MD5")
	}
}

func TestIsScannable(t *testing.T) {
	tests := map[string]bool{
		".go": true, ".py": true, ".js": true, ".java": true,
		".tf": true, ".pem": true, ".exe": false, ".png": false,
	}
	for ext, want := range tests {
		if got := isScannable(ext); got != want {
			t.Errorf("isScannable(%s) = %v, want %v", ext, got, want)
		}
	}
}
