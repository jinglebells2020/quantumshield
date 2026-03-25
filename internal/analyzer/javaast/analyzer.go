// Package javaast provides regex-enhanced analysis for detecting
// quantum-vulnerable cryptographic usage in Java source files. It uses
// multi-line regex and variable tracking (taint resolution) to detect
// crypto patterns without requiring a Java runtime.
package javaast

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// Analyzer performs enhanced Java crypto analysis with variable tracking.
type Analyzer struct{}

// New creates a new Java AST analyzer.
func New() *Analyzer { return &Analyzer{} }

// rule defines a single regex-based detection pattern.
type rule struct {
	pattern *regexp.Regexp
	algo    string
	sev     models.Severity
	threat  models.QuantumThreatLevel
	cat     models.AlgorithmCategory
	id      string
	desc    string
	repl    string
}

// cipherRules returns the static rule set for Java crypto patterns.
func cipherRules() []rule {
	return []rule{
		// Cipher.getInstance with literal argument
		{regexp.MustCompile(`Cipher\.getInstance\("(DES)(?:/|")`), "DES", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-DES-001", "DES cipher", "AES-256-GCM"},
		{regexp.MustCompile(`Cipher\.getInstance\("DESede`), "3DES", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-3DES-001", "3DES cipher", "AES-256"},
		{regexp.MustCompile(`Cipher\.getInstance\("AES/ECB`), "AES-ECB", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-AES-ECB-001", "AES-ECB mode (no IV)", "AES-GCM"},
		{regexp.MustCompile(`Cipher\.getInstance\("RSA`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JAVA-RSA-001", "RSA cipher", "ML-KEM-768"},
		{regexp.MustCompile(`Cipher\.getInstance\("Blowfish`), "Blowfish", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-BF-001", "Blowfish cipher", "AES-256"},
		{regexp.MustCompile(`Cipher\.getInstance\("RC4`), "RC4", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-RC4-001", "RC4 cipher", "AES-256-GCM"},

		// KeyPairGenerator
		{regexp.MustCompile(`KeyPairGenerator\.getInstance\("RSA"\)`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JAVA-RSA-KPG-001", "RSA key pair generation", "ML-KEM-768"},
		{regexp.MustCompile(`KeyPairGenerator\.getInstance\("EC"\)`), "ECDSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-EC-001", "EC key pair generation", "ML-DSA-65"},
		{regexp.MustCompile(`KeyPairGenerator\.getInstance\("DSA"\)`), "DSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-DSA-001", "DSA key pair generation", "ML-DSA-65"},
		{regexp.MustCompile(`KeyPairGenerator\.getInstance\("DH"\)`), "DH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JAVA-DH-001", "DH key pair generation", "ML-KEM-768"},

		// KeyGenerator
		{regexp.MustCompile(`KeyGenerator\.getInstance\("DES"\)`), "DES", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-DES-KG-001", "DES key generation", "AES-256"},
		{regexp.MustCompile(`KeyGenerator\.getInstance\("DESede"\)`), "3DES", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JAVA-3DES-KG-001", "3DES key generation", "AES-256"},

		// MessageDigest
		{regexp.MustCompile(`MessageDigest\.getInstance\("MD5"`), "MD5", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JAVA-MD5-001", "MD5 hash", "SHA-256"},
		{regexp.MustCompile(`MessageDigest\.getInstance\("MD2"`), "MD2", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JAVA-MD2-001", "MD2 hash", "SHA-256"},
		{regexp.MustCompile(`MessageDigest\.getInstance\("SHA-?1"`), "SHA-1", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JAVA-SHA1-001", "SHA-1 hash", "SHA-256"},

		// Signature
		{regexp.MustCompile(`Signature\.getInstance\(".*withRSA"`), "RSA-Signature", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-RSA-SIG-001", "RSA signature", "ML-DSA-65"},
		{regexp.MustCompile(`Signature\.getInstance\(".*withECDSA"`), "ECDSA-Signature", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-ECDSA-SIG-001", "ECDSA signature", "ML-DSA-65"},
		{regexp.MustCompile(`Signature\.getInstance\(".*withDSA"`), "DSA-Signature", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-DSA-SIG-001", "DSA signature", "ML-DSA-65"},

		// KeyAgreement
		{regexp.MustCompile(`KeyAgreement\.getInstance\("ECDH"\)`), "ECDH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JAVA-ECDH-001", "ECDH key agreement", "ML-KEM-768"},
		{regexp.MustCompile(`KeyAgreement\.getInstance\("DH"\)`), "DH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JAVA-DH-KA-001", "DH key agreement", "ML-KEM-768"},

		// Bouncy Castle
		{regexp.MustCompile(`new RSAKeyPairGenerator`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JAVA-BC-RSA-001", "Bouncy Castle RSA", "ML-KEM-768"},
		{regexp.MustCompile(`new ECKeyPairGenerator`), "ECDSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JAVA-BC-EC-001", "Bouncy Castle ECDSA", "ML-DSA-65"},
	}
}

var (
	varAssignPattern    = regexp.MustCompile(`(?:String|var)\s+(\w+)\s*=\s*(?:.*\.getProperty\(|.*\.get\(|)"?(DES(?:ede)?|RSA|MD[25]|SHA-?1|AES|Blowfish|RC4|EC|DSA|DH)"?`)
	getInstanceVarPat   = regexp.MustCompile(`(?:Cipher|MessageDigest|KeyPairGenerator|KeyGenerator|Signature|KeyAgreement)\.getInstance\((\w+)`)
	initializePattern   = regexp.MustCompile(`\.initialize\((\d+)\)`)
)

// AnalyzeFile performs enhanced Java crypto analysis with variable tracking.
func (a *Analyzer) AnalyzeFile(filePath string, content []byte) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(string(content), "\n")

	// Track variable assignments for taint resolution.
	vars := make(map[string]string) // varName -> value

	rules := cipherRules()

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments and imports.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.HasPrefix(trimmed, "import ") {
			continue
		}

		// Track variable assignments.
		if m := varAssignPattern.FindStringSubmatch(line); len(m) >= 3 {
			vars[m[1]] = m[2]
		}

		// Check direct patterns.
		for _, r := range rules {
			if r.pattern.MatchString(line) {
				findings = append(findings, models.Finding{
					ID:              fmt.Sprintf("javaast-%s-%d-%s", filepath.Base(filePath), lineNum, r.id),
					RuleID:          r.id,
					Severity:        r.sev,
					Category:        r.cat,
					QuantumThreat:   r.threat,
					FilePath:        filePath,
					LineStart:       lineNum,
					LineEnd:         lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       r.algo,
					Language:        "java",
					Description:     r.desc,
					ReplacementAlgo: r.repl,
					Confidence:      0.93,
					CreatedAt:       time.Now(),
				})
				break // One finding per line.
			}
		}

		// Check variable-argument patterns (taint resolution).
		if m := getInstanceVarPat.FindStringSubmatch(line); len(m) >= 2 {
			varName := m[1]
			if resolved, ok := vars[varName]; ok {
				algo := resolved
				sev := models.SeverityHigh
				threat := models.ThreatWeakenedByGrover
				cat := models.CategorySymmetricEncryption
				repl := "AES-256"

				switch {
				case resolved == "RSA" || resolved == "EC" || resolved == "DSA" || resolved == "DH":
					sev = models.SeverityCritical
					threat = models.ThreatBrokenByShor
					cat = models.CategoryAsymmetricEncryption
					repl = "ML-KEM-768"
				case resolved == "DES" || resolved == "DESede":
					sev = models.SeverityCritical
				case resolved == "MD5" || resolved == "MD2" || strings.Contains(resolved, "SHA"):
					cat = models.CategoryHashing
					repl = "SHA-256"
				}

				findings = append(findings, models.Finding{
					ID:              fmt.Sprintf("javaast-%s-%d-taint", filepath.Base(filePath), lineNum),
					RuleID:          "QS-JAVA-TAINT-001",
					Severity:        sev,
					Category:        cat,
					QuantumThreat:   threat,
					FilePath:        filePath,
					LineStart:       lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       algo,
					Usage:           fmt.Sprintf("getInstance(%s) via variable %s", resolved, varName),
					Language:        "java",
					Description:     fmt.Sprintf("Crypto algorithm %s resolved from variable %s", resolved, varName),
					ReplacementAlgo: repl,
					Confidence:      0.85,
					CreatedAt:       time.Now(),
				})
			}
		}
	}

	// Extract key sizes from .initialize(N) calls.
	for i, line := range lines {
		if m := initializePattern.FindStringSubmatch(line); len(m) >= 2 {
			// Find the most recent finding near this line and attach the key size.
			for j := len(findings) - 1; j >= 0; j-- {
				if findings[j].FilePath == filePath && findings[j].LineStart <= i+1 && i+1-findings[j].LineStart < 5 {
					if n := parseInt(m[1]); n > 0 {
						findings[j].KeySize = n
						if findings[j].Algorithm == "RSA" || findings[j].Algorithm == "DSA" || findings[j].Algorithm == "DH" {
							findings[j].Algorithm = fmt.Sprintf("%s-%d", findings[j].Algorithm, n)
						}
					}
					break
				}
			}
		}
	}

	return findings
}

// AnalyzeDirectory scans all Java files in a directory.
func (a *Analyzer) AnalyzeDirectory(root string) ([]models.Finding, error) {
	var all []models.Finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			b := filepath.Base(path)
			if b == "vendor" || b == "node_modules" || b == ".git" || b == "target" || b == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".java") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		findings := a.AnalyzeFile(path, content)
		all = append(all, findings...)
		return nil
	})
	return all, err
}

// parseInt parses a decimal integer from a string without importing strconv.
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
