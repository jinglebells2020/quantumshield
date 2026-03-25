package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"quantumshield/pkg/models"
)

type Reporter struct {
	format string
}

func New(format string) *Reporter {
	return &Reporter{format: format}
}

func (r *Reporter) Write(w io.Writer, result *models.ScanResult) error {
	switch r.format {
	case "json":
		return r.writeJSON(w, result)
	case "sarif":
		return r.writeSARIF(w, result)
	case "table":
		return r.writeTable(w, result)
	default:
		return r.writeTable(w, result)
	}
}

func (r *Reporter) WriteFile(result *models.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.Write(f, result)
}

func (r *Reporter) writeJSON(w io.Writer, result *models.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func (r *Reporter) writeTable(w io.Writer, result *models.ScanResult) error {
	fmt.Fprintf(w, "\n  Scan completed in %dms\n", result.DurationMs)
	fmt.Fprintf(w, "  %d files scanned | %d rules evaluated\n\n", result.FilesScanned, result.RulesEvaluated)

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "  No quantum-vulnerable cryptography found!\n")
		fmt.Fprintf(w, "  Quantum Readiness: 100/100\n\n")
		return nil
	}

	// Sort by severity
	findings := make([]models.Finding, len(result.Findings))
	copy(findings, result.Findings)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity < findings[j].Severity
	})

	// Deduplicate by rule+file+line
	seen := make(map[string]bool)
	var deduped []models.Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	findings = deduped

	fmt.Fprintf(w, "  FINDINGS: %d total", len(findings))
	if result.Summary.BySeverity["CRITICAL"] > 0 {
		fmt.Fprintf(w, " (%d Critical", result.Summary.BySeverity["CRITICAL"])
		if result.Summary.BySeverity["HIGH"] > 0 {
			fmt.Fprintf(w, ", %d High", result.Summary.BySeverity["HIGH"])
		}
		if result.Summary.BySeverity["MEDIUM"] > 0 {
			fmt.Fprintf(w, ", %d Medium", result.Summary.BySeverity["MEDIUM"])
		}
		fmt.Fprintf(w, ")")
	}
	fmt.Fprintf(w, "\n\n")

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  SEVERITY\tALGORITHM\tLOCATION\tTHREAT\tREPLACEMENT\n")
	fmt.Fprintf(tw, "  --------\t---------\t--------\t------\t-----------\n")

	for _, f := range findings {
		loc := fmt.Sprintf("%s:%d", shortenPath(f.FilePath), f.LineStart)
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			colorSeverity(f.Severity),
			f.Algorithm,
			loc,
			f.QuantumThreat.String(),
			f.ReplacementAlgo,
		)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n")

	// Risk summary
	readiness := result.Summary.QuantumReadiness
	bar := renderBar(readiness, 20)
	fmt.Fprintf(w, "  QUANTUM READINESS: %.0f/100 %s\n\n", readiness, bar)

	// Migration estimate
	autofix := 0
	manual := 0
	for _, f := range findings {
		if f.AutoFixAvailable {
			autofix++
		} else {
			manual++
		}
	}
	fmt.Fprintf(w, "  MIGRATION ESTIMATE:\n")
	fmt.Fprintf(w, "    Auto-fixable:  %d/%d findings\n", autofix, len(findings))
	fmt.Fprintf(w, "    Manual:        %d/%d findings\n\n", manual, len(findings))

	return nil
}

func colorSeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "\033[91mCRITICAL\033[0m"
	case models.SeverityHigh:
		return "\033[93mHIGH\033[0m"
	case models.SeverityMedium:
		return "\033[33mMEDIUM\033[0m"
	case models.SeverityLow:
		return "\033[36mLOW\033[0m"
	default:
		return s.String()
	}
}

func shortenPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) > 3 {
		return strings.Join(parts[len(parts)-3:], "/")
	}
	return p
}

func renderBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("\033[42m \033[0m", filled) + strings.Repeat("\033[41m \033[0m", width-filled)
}

func (r *Reporter) writeSARIF(w io.Writer, result *models.ScanResult) error {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "QuantumShield",
						"version": "0.1.0",
						"rules":   buildSARIFRules(result.Findings),
					},
				},
				"results": buildSARIFResults(result.Findings),
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func buildSARIFRules(findings []models.Finding) []map[string]interface{} {
	seen := make(map[string]bool)
	var sarifRules []map[string]interface{}
	for _, f := range findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		sarifRules = append(sarifRules, map[string]interface{}{
			"id":   f.RuleID,
			"name": f.Algorithm,
			"shortDescription": map[string]string{
				"text": f.Description,
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(f.Severity),
			},
		})
	}
	return sarifRules
}

func buildSARIFResults(findings []models.Finding) []map[string]interface{} {
	var results []map[string]interface{}
	for _, f := range findings {
		results = append(results, map[string]interface{}{
			"ruleId":  f.RuleID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]string{"text": f.Description},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": f.FilePath},
						"region": map[string]int{
							"startLine":   f.LineStart,
							"startColumn": f.ColumnStart,
						},
					},
				},
			},
		})
	}
	return results
}

func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
