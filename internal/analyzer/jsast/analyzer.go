// Package jsast provides regex-enhanced analysis for detecting
// quantum-vulnerable cryptographic usage in JavaScript and TypeScript
// source files. It uses multi-line regex and variable tracking to detect
// crypto patterns from Node.js crypto, Web Crypto API, node-forge, and
// NodeRSA without requiring a JS runtime.
package jsast

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// Analyzer performs enhanced JS/TS crypto analysis with variable tracking.
type Analyzer struct{}

// New creates a new JavaScript/TypeScript analyzer.
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

// cryptoRules returns the static rule set for JS/TS crypto patterns.
func cryptoRules() []rule {
	return []rule{
		// --- Node.js crypto module ---

		// crypto.createHash
		{regexp.MustCompile(`crypto\.createHash\(\s*['"]md5['"]\s*\)`), "MD5", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-MD5-001", "MD5 hash via crypto.createHash", "SHA-256"},
		{regexp.MustCompile(`crypto\.createHash\(\s*['"]sha1?['"]\s*\)`), "SHA-1", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-SHA1-001", "SHA-1 hash via crypto.createHash", "SHA-256"},
		{regexp.MustCompile(`crypto\.createHash\(\s*['"]md4['"]\s*\)`), "MD4", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-MD4-001", "MD4 hash via crypto.createHash", "SHA-256"},
		{regexp.MustCompile(`crypto\.createHash\(\s*['"]ripemd160['"]\s*\)`), "RIPEMD-160", models.SeverityMedium, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-RIPEMD-001", "RIPEMD-160 hash", "SHA-256"},

		// crypto.createCipheriv / createCipher
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]des(?:-ede3)?-`), "DES/3DES", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-DES-001", "DES/3DES cipher", "AES-256-GCM"},
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]aes-128-cbc['"]\s*,`), "AES-128-CBC", models.SeverityMedium, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-AES128CBC-001", "AES-128-CBC cipher (weak key + no auth)", "AES-256-GCM"},
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]aes-128-ecb['"]\s*,`), "AES-128-ECB", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-AES128ECB-001", "AES-128-ECB cipher (no IV)", "AES-256-GCM"},
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]aes-256-ecb['"]\s*,`), "AES-256-ECB", models.SeverityMedium, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-AES256ECB-001", "AES-256-ECB cipher (no IV)", "AES-256-GCM"},
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]rc4['"]\s*,`), "RC4", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-RC4-001", "RC4 cipher", "AES-256-GCM"},
		{regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*['"]bf-`), "Blowfish", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-BF-001", "Blowfish cipher", "AES-256-GCM"},

		// crypto.generateKeyPairSync / generateKeyPair
		{regexp.MustCompile(`crypto\.generateKeyPair(?:Sync)?\(\s*['"]rsa['"]\s*,`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-RSA-KPG-001", "RSA key pair generation", "ML-KEM-768"},
		{regexp.MustCompile(`crypto\.generateKeyPair(?:Sync)?\(\s*['"]ec['"]\s*,`), "ECDSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-EC-KPG-001", "EC key pair generation", "ML-DSA-65"},
		{regexp.MustCompile(`crypto\.generateKeyPair(?:Sync)?\(\s*['"]dsa['"]\s*,`), "DSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-DSA-KPG-001", "DSA key pair generation", "ML-DSA-65"},

		// crypto.createSign
		{regexp.MustCompile(`crypto\.createSign\(\s*['"](?:SHA1|RSA-SHA1)['"]\s*\)`), "SHA-1", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryDigitalSignature, "QS-JS-SHA1-SIG-001", "SHA-1 based signature", "SHA-256"},
		{regexp.MustCompile(`crypto\.createSign\(\s*['"](?:RSA-MD5|md5)['"]\s*\)`), "MD5", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryDigitalSignature, "QS-JS-MD5-SIG-001", "MD5 based signature", "SHA-256"},

		// crypto.createDiffieHellman / createECDH
		{regexp.MustCompile(`crypto\.createDiffieHellman\(`), "DH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-DH-001", "Diffie-Hellman key exchange", "ML-KEM-768"},
		{regexp.MustCompile(`crypto\.createECDH\(\s*['"]secp256k1['"]\s*\)`), "ECDH-secp256k1", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-ECDH-K1-001", "ECDH key exchange (secp256k1)", "ML-KEM-768"},
		{regexp.MustCompile(`crypto\.createECDH\(\s*['"]prime256v1['"]\s*\)`), "ECDH-P256", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-ECDH-P256-001", "ECDH key exchange (P-256)", "ML-KEM-768"},
		{regexp.MustCompile(`crypto\.createECDH\(`), "ECDH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-ECDH-001", "ECDH key exchange", "ML-KEM-768"},

		// crypto.publicEncrypt / privateDecrypt (implies RSA)
		{regexp.MustCompile(`crypto\.publicEncrypt\(`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-RSA-ENC-001", "RSA public key encryption", "ML-KEM-768"},

		// --- Web Crypto API (crypto.subtle) ---

		// crypto.subtle.generateKey RSA
		{regexp.MustCompile(`crypto\.subtle\.generateKey\(\s*\{[^}]*name\s*:\s*['"]RSA-OAEP['"]\s*`), "RSA-OAEP", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-WC-RSA-OAEP-001", "Web Crypto RSA-OAEP key generation", "ML-KEM-768"},
		{regexp.MustCompile(`crypto\.subtle\.generateKey\(\s*\{[^}]*name\s*:\s*['"]RSA-PSS['"]\s*`), "RSA-PSS", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-WC-RSA-PSS-001", "Web Crypto RSA-PSS key generation", "ML-DSA-65"},
		{regexp.MustCompile(`crypto\.subtle\.generateKey\(\s*\{[^}]*name\s*:\s*['"]RSASSA-PKCS1-v1_5['"]\s*`), "RSA-PKCS1", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-WC-RSA-PKCS-001", "Web Crypto RSA PKCS#1 v1.5 signature", "ML-DSA-65"},

		// crypto.subtle.generateKey ECDSA / ECDH
		{regexp.MustCompile(`crypto\.subtle\.generateKey\(\s*\{[^}]*name\s*:\s*['"]ECDSA['"]\s*`), "ECDSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-WC-ECDSA-001", "Web Crypto ECDSA key generation", "ML-DSA-65"},
		{regexp.MustCompile(`crypto\.subtle\.generateKey\(\s*\{[^}]*name\s*:\s*['"]ECDH['"]\s*`), "ECDH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-WC-ECDH-001", "Web Crypto ECDH key generation", "ML-KEM-768"},

		// --- Third-party libraries ---

		// NodeRSA
		{regexp.MustCompile(`new\s+NodeRSA\(`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-NODERSA-001", "NodeRSA key generation", "ML-KEM-768"},

		// node-forge RSA
		{regexp.MustCompile(`forge\.pki\.rsa\.generateKeyPair\(`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-FORGE-RSA-001", "node-forge RSA key generation", "ML-KEM-768"},
		{regexp.MustCompile(`forge\.md\.md5\.create\(\)`), "MD5", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-FORGE-MD5-001", "node-forge MD5 digest", "SHA-256"},
		{regexp.MustCompile(`forge\.md\.sha1\.create\(\)`), "SHA-1", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-JS-FORGE-SHA1-001", "node-forge SHA-1 digest", "SHA-256"},
		{regexp.MustCompile(`forge\.rc2\.createEncryptionCipher\(`), "RC2", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-JS-FORGE-RC2-001", "node-forge RC2 cipher", "AES-256-GCM"},

		// jsencrypt (RSA)
		{regexp.MustCompile(`new\s+JSEncrypt\(`), "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-JS-JSENCRYPT-001", "JSEncrypt RSA", "ML-KEM-768"},

		// tweetnacl / libsodium (not quantum-safe but commonly assumed safe)
		// We flag ECDH/Ed25519 as needing attention for quantum migration
		{regexp.MustCompile(`nacl\.box\(`), "Curve25519-XSalsa20", models.SeverityHigh, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-JS-NACL-BOX-001", "NaCl box (Curve25519 key exchange)", "ML-KEM-768"},
		{regexp.MustCompile(`nacl\.sign\(`), "Ed25519", models.SeverityHigh, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-JS-NACL-SIGN-001", "NaCl sign (Ed25519)", "ML-DSA-65"},
	}
}

var (
	// modulusLenPattern extracts modulusLength from generateKeyPairSync / generateKey options.
	modulusLenPattern = regexp.MustCompile(`modulusLength\s*:\s*(\d+)`)
	// nodeRSABitsPattern extracts bits from new NodeRSA({b: N}).
	nodeRSABitsPattern = regexp.MustCompile(`new\s+NodeRSA\(\s*\{[^}]*b\s*:\s*(\d+)`)
	// forgeBitsPattern extracts bits from forge.pki.rsa.generateKeyPair({bits: N}).
	forgeBitsPattern = regexp.MustCompile(`forge\.pki\.rsa\.generateKeyPair\(\s*\{[^}]*bits\s*:\s*(\d+)`)
	// dhSizePattern extracts size from crypto.createDiffieHellman(N).
	dhSizePattern = regexp.MustCompile(`crypto\.createDiffieHellman\(\s*(\d+)\s*\)`)
	// namedCurvePattern extracts namedCurve from Web Crypto API options.
	namedCurvePattern = regexp.MustCompile(`namedCurve\s*:\s*['"]([^'"]+)['"]`)
	// varAssignPattern tracks variable assignments for taint resolution.
	varAssignAlgoPattern = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*['"](\w[\w-]*)['"]\s*;?`)
	// createHashVarPattern matches crypto.createHash(varName).
	createHashVarPattern = regexp.MustCompile(`crypto\.createHash\(\s*(\w+)\s*\)`)
	// createCipherVarPattern matches crypto.createCipher[iv](varName, ...).
	createCipherVarPattern = regexp.MustCompile(`crypto\.createCipher(?:iv)?\(\s*(\w+)\s*,`)
)

// AnalyzeFile performs enhanced JS/TS crypto analysis with variable tracking.
func (a *Analyzer) AnalyzeFile(filePath string, content []byte) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(string(content), "\n")

	// Track variable assignments for taint resolution.
	vars := make(map[string]string) // varName -> value

	rules := cryptoRules()

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip single-line comments.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Track variable assignments for taint resolution.
		if m := varAssignAlgoPattern.FindStringSubmatch(line); len(m) >= 3 {
			vars[m[1]] = m[2]
		}

		// Check direct patterns.
		matched := false
		for _, r := range rules {
			if r.pattern.MatchString(line) {
				f := models.Finding{
					ID:              fmt.Sprintf("jsast-%s-%d-%s", filepath.Base(filePath), lineNum, r.id),
					RuleID:          r.id,
					Severity:        r.sev,
					Category:        r.cat,
					QuantumThreat:   r.threat,
					FilePath:        filePath,
					LineStart:       lineNum,
					LineEnd:         lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       r.algo,
					Language:        detectLang(filePath),
					Description:     r.desc,
					ReplacementAlgo: r.repl,
					Confidence:      0.92,
					CreatedAt:       time.Now(),
				}

				// Try to extract key size from the same line or nearby context.
				a.enrichKeySize(&f, line, lines, i)

				findings = append(findings, f)
				matched = true
				break // One finding per line.
			}
		}

		// Check variable-argument patterns (taint resolution).
		if !matched {
			a.checkTaintedCalls(line, lineNum, filePath, trimmed, vars, &findings)
		}
	}

	return findings
}

// enrichKeySize attempts to extract key size from the line or nearby lines.
func (a *Analyzer) enrichKeySize(f *models.Finding, line string, lines []string, idx int) {
	// Check the current line and up to 3 lines below for modulusLength/bits.
	searchBlock := line
	end := idx + 4
	if end > len(lines) {
		end = len(lines)
	}
	for j := idx; j < end; j++ {
		searchBlock += " " + lines[j]
	}

	switch {
	case strings.Contains(f.RuleID, "RSA") || strings.Contains(f.Algorithm, "RSA"):
		if m := modulusLenPattern.FindStringSubmatch(searchBlock); len(m) >= 2 {
			if n := parseInt(m[1]); n > 0 {
				f.KeySize = n
				f.Algorithm = fmt.Sprintf("RSA-%d", n)
			}
		}
		if m := nodeRSABitsPattern.FindStringSubmatch(searchBlock); len(m) >= 2 {
			if n := parseInt(m[1]); n > 0 {
				f.KeySize = n
				f.Algorithm = fmt.Sprintf("RSA-%d", n)
			}
		}
		if m := forgeBitsPattern.FindStringSubmatch(searchBlock); len(m) >= 2 {
			if n := parseInt(m[1]); n > 0 {
				f.KeySize = n
				f.Algorithm = fmt.Sprintf("RSA-%d", n)
			}
		}
	case strings.Contains(f.RuleID, "DH-001"):
		if m := dhSizePattern.FindStringSubmatch(searchBlock); len(m) >= 2 {
			if n := parseInt(m[1]); n > 0 {
				f.KeySize = n
				f.Algorithm = fmt.Sprintf("DH-%d", n)
			}
		}
	case strings.Contains(f.RuleID, "ECDSA") || strings.Contains(f.RuleID, "ECDH"):
		if m := namedCurvePattern.FindStringSubmatch(searchBlock); len(m) >= 2 {
			curve := m[1]
			f.Algorithm = fmt.Sprintf("%s-%s", f.Algorithm, curve)
		}
	}
}

// checkTaintedCalls checks if a crypto API is called with a variable whose
// value was previously assigned to an algorithm string.
func (a *Analyzer) checkTaintedCalls(line string, lineNum int, filePath, trimmed string, vars map[string]string, findings *[]models.Finding) {
	// crypto.createHash(variable)
	if m := createHashVarPattern.FindStringSubmatch(line); len(m) >= 2 {
		if resolved, ok := vars[m[1]]; ok {
			lower := strings.ToLower(resolved)
			if lower == "md5" || lower == "sha1" || lower == "sha-1" || lower == "md4" {
				*findings = append(*findings, models.Finding{
					ID:              fmt.Sprintf("jsast-%s-%d-taint", filepath.Base(filePath), lineNum),
					RuleID:          "QS-JS-TAINT-001",
					Severity:        models.SeverityHigh,
					Category:        models.CategoryHashing,
					QuantumThreat:   models.ThreatWeakenedByGrover,
					FilePath:        filePath,
					LineStart:       lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       strings.ToUpper(resolved),
					Usage:           fmt.Sprintf("createHash(%s) via variable %s", resolved, m[1]),
					Language:        detectLang(filePath),
					Description:     fmt.Sprintf("Weak hash %s resolved from variable %s", resolved, m[1]),
					ReplacementAlgo: "SHA-256",
					Confidence:      0.83,
					CreatedAt:       time.Now(),
				})
			}
		}
	}

	// crypto.createCipher[iv](variable, ...)
	if m := createCipherVarPattern.FindStringSubmatch(line); len(m) >= 2 {
		if resolved, ok := vars[m[1]]; ok {
			lower := strings.ToLower(resolved)
			if strings.Contains(lower, "des") || strings.Contains(lower, "rc4") || strings.Contains(lower, "bf-") {
				*findings = append(*findings, models.Finding{
					ID:              fmt.Sprintf("jsast-%s-%d-taint", filepath.Base(filePath), lineNum),
					RuleID:          "QS-JS-TAINT-002",
					Severity:        models.SeverityHigh,
					Category:        models.CategorySymmetricEncryption,
					QuantumThreat:   models.ThreatWeakenedByGrover,
					FilePath:        filePath,
					LineStart:       lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       resolved,
					Usage:           fmt.Sprintf("createCipher(%s) via variable %s", resolved, m[1]),
					Language:        detectLang(filePath),
					Description:     fmt.Sprintf("Weak cipher %s resolved from variable %s", resolved, m[1]),
					ReplacementAlgo: "AES-256-GCM",
					Confidence:      0.83,
					CreatedAt:       time.Now(),
				})
			}
		}
	}
}

// AnalyzeDirectory scans all JS/TS files in a directory.
func (a *Analyzer) AnalyzeDirectory(root string) ([]models.Finding, error) {
	var all []models.Finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			b := filepath.Base(path)
			if b == "vendor" || b == "node_modules" || b == ".git" || b == "dist" || b == "build" || b == ".next" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".js" && ext != ".ts" && ext != ".jsx" && ext != ".tsx" && ext != ".mjs" && ext != ".cjs" {
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

// detectLang returns "javascript" or "typescript" based on file extension.
func detectLang(filePath string) string {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".ts", ".tsx":
		return "typescript"
	default:
		return "javascript"
	}
}

// parseInt parses a decimal integer from a string.
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
