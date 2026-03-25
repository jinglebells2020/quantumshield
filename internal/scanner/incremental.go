package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"quantumshield/pkg/models"
)

// IncrementalResult contains only new and fixed findings relative to baseline.
type IncrementalResult struct {
	NewFindings   []models.Finding `json:"new_findings"`
	FixedFindings []models.Finding `json:"fixed_findings"`
	NewCount      int              `json:"new_count"`
	FixedCount    int              `json:"fixed_count"`
	BaselineID    string           `json:"baseline_id"`
	ChangedFiles  []string         `json:"changed_files"`
}

// BaselineStore manages scan baselines for incremental scanning.
type BaselineStore struct {
	path string // .quantumshield/baseline.json
}

type Baseline struct {
	ScanID   string           `json:"scan_id"`
	Findings []models.Finding `json:"findings"`
	Branch   string           `json:"branch"`
}

// NewBaselineStore creates a baseline store at the given project root.
func NewBaselineStore(projectRoot string) *BaselineStore {
	return &BaselineStore{path: filepath.Join(projectRoot, ".quantumshield", "baseline.json")}
}

// Save persists a baseline to disk.
func (bs *BaselineStore) Save(baseline *Baseline) error {
	dir := filepath.Dir(bs.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bs.path, data, 0644)
}

// Load reads the baseline from disk. Returns nil if no baseline exists.
func (bs *BaselineStore) Load() (*Baseline, error) {
	data, err := os.ReadFile(bs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// GetChangedFiles returns files changed since the given git ref (e.g., "origin/main").
func GetChangedFiles(repoRoot, baseRef string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef+"..HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		// Fallback: try without ..HEAD (might be on same branch)
		cmd = exec.Command("git", "diff", "--name-only", baseRef)
		cmd.Dir = repoRoot
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff failed: %w", err)
		}
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// Only include scannable files
		ext := filepath.Ext(line)
		if isScannable(ext) {
			files = append(files, filepath.Join(repoRoot, line))
		}
	}
	return files, nil
}

func isScannable(ext string) bool {
	scannable := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".conf": true, ".yaml": true, ".yml": true, ".toml": true,
		".pem": true, ".crt": true, ".cer": true, ".tf": true,
	}
	return scannable[ext]
}

// ComputeDiff compares current findings against baseline and returns new/fixed findings.
func ComputeDiff(baseline *Baseline, current []models.Finding) *IncrementalResult {
	result := &IncrementalResult{BaselineID: baseline.ScanID}

	baseMap := make(map[string]models.Finding)
	for _, f := range baseline.Findings {
		key := fingerprintFinding(f)
		baseMap[key] = f
	}

	currMap := make(map[string]models.Finding)
	for _, f := range current {
		key := fingerprintFinding(f)
		currMap[key] = f
	}

	// New findings: in current but not baseline
	for key, f := range currMap {
		if _, exists := baseMap[key]; !exists {
			result.NewFindings = append(result.NewFindings, f)
			result.NewCount++
		}
	}

	// Fixed findings: in baseline but not current
	for key, f := range baseMap {
		if _, exists := currMap[key]; !exists {
			result.FixedFindings = append(result.FixedFindings, f)
			result.FixedCount++
		}
	}

	return result
}

func fingerprintFinding(f models.Finding) string {
	return fmt.Sprintf("%s:%d:%s:%s", filepath.Base(f.FilePath), f.LineStart, f.RuleID, f.Algorithm)
}
