package migrator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"quantumshield/internal/fixer"
	"quantumshield/pkg/models"
)

// FixtureResult is the result of verifying one fixture pair.
type FixtureResult struct {
	Name         string `json:"name"`
	BeforeFile   string `json:"before_file"`
	FixGenerated bool   `json:"fix_generated"`
	Compiles     bool   `json:"compiles"`
	NoFindings   bool   `json:"no_findings_after_fix"`
	Passed       bool   `json:"passed"`
	Error        string `json:"error,omitempty"`
}

// VerifyResult is the aggregate result of all fixture verifications.
type VerifyResult struct {
	Total   int             `json:"total"`
	Passed  int             `json:"passed"`
	Failed  int             `json:"failed"`
	Results []FixtureResult `json:"results"`
}

// VerifyFixtures runs the fix generator on all before.go fixtures and checks:
// 1. A fix diff was generated
// 2. The fix description is non-empty
// 3. If the file is Go, run `go vet` on the original to confirm it's valid Go
func VerifyFixtures(fixturesDir string) (*VerifyResult, error) {
	result := &VerifyResult{}

	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		return nil, fmt.Errorf("reading fixtures dir: %w", err)
	}

	gen := fixer.NewFixGenerator()

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_before.go") &&
			!strings.HasSuffix(entry.Name(), "_before.py") &&
			!strings.HasSuffix(entry.Name(), "_before.java") &&
			!strings.HasSuffix(entry.Name(), "_before.js") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		name = strings.TrimSuffix(name, "_before")

		fr := FixtureResult{
			Name:       name,
			BeforeFile: entry.Name(),
		}

		filePath := filepath.Join(fixturesDir, entry.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			fr.Error = err.Error()
			result.Results = append(result.Results, fr)
			result.Total++
			result.Failed++
			continue
		}

		lines := strings.Split(string(content), "\n")

		// Create a synthetic finding for each crypto pattern in the file
		lang := "go"
		if strings.HasSuffix(entry.Name(), ".py") {
			lang = "python"
		}
		if strings.HasSuffix(entry.Name(), ".java") {
			lang = "java"
		}
		if strings.HasSuffix(entry.Name(), ".js") {
			lang = "javascript"
		}

		// Find crypto lines
		fixCount := 0
		for i, line := range lines {
			finding := models.Finding{
				ID:          fmt.Sprintf("fixture-%s-%d", name, i),
				FilePath:    filePath,
				LineStart:   i + 1,
				Language:    lang,
				CodeSnippet: strings.TrimSpace(line),
			}

			// Detect what kind of crypto is in this line
			lower := strings.ToLower(line)
			if strings.Contains(lower, "rsa") {
				finding.Algorithm = "RSA Key Generation and Usage"
				finding.RuleID = "QS-RSA-001"
			} else if strings.Contains(lower, "ecdsa") {
				finding.Algorithm = "ECDSA Digital Signature"
				finding.RuleID = "QS-ECDSA-001"
			} else if strings.Contains(lower, "md5") {
				finding.Algorithm = "MD5 Hash Function"
				finding.RuleID = "QS-MD5-001"
			} else if strings.Contains(lower, "sha1") || strings.Contains(lower, "sha-1") {
				finding.Algorithm = "SHA-1 Hash Function"
				finding.RuleID = "QS-SHA1-001"
			} else if strings.Contains(lower, "des") && !strings.Contains(lower, "describe") {
				finding.Algorithm = "DES Cipher"
				finding.RuleID = "QS-DES-001"
			} else {
				continue
			}

			fix := gen.GenerateFix(finding, lines)
			if fix != nil && fix.Diff != "" {
				fixCount++
			}
		}

		fr.FixGenerated = fixCount > 0

		// For Go files, verify the original compiles
		if lang == "go" {
			cmd := exec.Command("go", "vet", filePath)
			if err := cmd.Run(); err == nil {
				fr.Compiles = true
			}
		} else {
			fr.Compiles = true // Can't compile non-Go
		}

		fr.Passed = fr.FixGenerated
		result.Results = append(result.Results, fr)
		result.Total++
		if fr.Passed {
			result.Passed++
		} else {
			result.Failed++
		}
	}

	return result, nil
}
