package fixer

import (
	"fmt"
	"strings"

	"quantumshield/pkg/models"
)

// FixResult contains a generated fix for a finding.
type FixResult struct {
	FindingID   string  `json:"finding_id"`
	FilePath    string  `json:"file_path"`
	Language    string  `json:"language"`
	Algorithm   string  `json:"algorithm"`
	Replacement string  `json:"replacement"`
	Diff        string  `json:"diff"`        // Unified diff format
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`  // How reliable is this fix
}

// FixGenerator produces code fixes for crypto findings.
type FixGenerator struct{}

// NewFixGenerator creates a new fix generator.
func NewFixGenerator() *FixGenerator {
	return &FixGenerator{}
}

// fixStrategy describes how to replace a vulnerable pattern.
type fixStrategy struct {
	oldContains string   // substring that the source line must contain
	newLines    []string // replacement lines
	description string
	confidence  float64
}

// goStrategies returns fix strategies for Go code.
func goStrategies() []fixStrategy {
	return []fixStrategy{
		{
			oldContains: "rsa.GenerateKey",
			newLines: []string{
				"\t// MIGRATION: Replace RSA-2048 with ML-KEM-768 (Post-Quantum)",
				"\t// See: https://pkg.go.dev/crypto/mlkem",
				"\t// Hybrid approach: use ML-KEM-768 for key encapsulation alongside RSA during transition",
				"\tdecapsulationKey, err := mlkem.GenerateKey768()",
			},
			description: "Replace RSA key generation with ML-KEM-768 post-quantum key encapsulation",
			confidence:  0.7,
		},
		{
			oldContains: "ecdsa.GenerateKey",
			newLines: []string{
				"\t// MIGRATION: Replace ECDSA-P256 with ML-DSA-65 (Post-Quantum Dilithium)",
				"\t// Hybrid approach recommended during transition period",
				"\tprivateKey, err := mldsa.GenerateKey65()",
			},
			description: "Replace ECDSA key generation with ML-DSA-65 post-quantum digital signature",
			confidence:  0.7,
		},
		{
			oldContains: "md5.New()",
			newLines:    []string{"\th := sha256.New()"},
			description: "Replace MD5 with SHA-256 (quantum-resistant hash)",
			confidence:  0.95,
		},
		{
			oldContains: "sha1.New()",
			newLines:    []string{"\th := sha256.New()"},
			description: "Replace SHA-1 with SHA-256 (quantum-resistant hash)",
			confidence:  0.95,
		},
		{
			oldContains: "tls.VersionTLS12",
			newLines:    []string{strings.Replace("\ttls.VersionTLS12", "tls.VersionTLS12", "tls.VersionTLS13", 1)},
			description: "Upgrade minimum TLS version from 1.2 to 1.3",
			confidence:  0.95,
		},
		{
			oldContains: "cipher.NewCBCEncrypter",
			newLines: []string{
				"\t// MIGRATION: Replace AES-CBC with AES-GCM (authenticated encryption)",
				"\t// AES-GCM provides both confidentiality and integrity",
				"\tblock, err := aes.NewCipher(key)",
				"\taesGCM, err := cipher.NewGCM(block)",
			},
			description: "Replace AES-CBC with AES-GCM authenticated encryption",
			confidence:  0.5,
		},
		{
			oldContains: "des.",
			newLines: []string{
				"\t// MIGRATION: Replace DES with AES-256-GCM",
				"\t// DES is broken; use AES-256-GCM for symmetric encryption",
				"\tblock, err := aes.NewCipher(key) // use 32-byte key for AES-256",
				"\taesGCM, err := cipher.NewGCM(block)",
			},
			description: "Replace DES with AES-256-GCM",
			confidence:  0.5,
		},
		{
			oldContains: "rc4.",
			newLines: []string{
				"\t// MIGRATION: Replace RC4 with AES-256-GCM",
				"\t// RC4 is broken; use AES-256-GCM for symmetric encryption",
				"\tblock, err := aes.NewCipher(key) // use 32-byte key for AES-256",
				"\taesGCM, err := cipher.NewGCM(block)",
			},
			description: "Replace RC4 with AES-256-GCM",
			confidence:  0.5,
		},
	}
}

// pythonStrategies returns fix strategies for Python code.
func pythonStrategies() []fixStrategy {
	return []fixStrategy{
		{
			oldContains: "rsa.generate_private_key(",
			newLines: []string{
				"    # MIGRATION: Replace RSA with ML-KEM (Post-Quantum)",
				"    # Install: pip install pqcrypto",
				"    # Hybrid approach: use ML-KEM for key encapsulation alongside RSA during transition",
				"    # from pqcrypto.kem.kyber768 import generate_keypair",
				"    # public_key, secret_key = generate_keypair()",
			},
			description: "Replace RSA key generation with ML-KEM post-quantum key encapsulation",
			confidence:  0.7,
		},
		{
			oldContains: "hashlib.md5(",
			newLines:    []string{strings.Replace("    hashlib.md5(", "hashlib.md5(", "hashlib.sha256(", 1)},
			description: "Replace MD5 with SHA-256",
			confidence:  0.95,
		},
		{
			oldContains: "hashlib.sha1(",
			newLines:    []string{strings.Replace("    hashlib.sha1(", "hashlib.sha1(", "hashlib.sha256(", 1)},
			description: "Replace SHA-1 with SHA-256",
			confidence:  0.95,
		},
	}
}

// javascriptStrategies returns fix strategies for JavaScript code.
func javascriptStrategies() []fixStrategy {
	return []fixStrategy{
		{
			oldContains: "crypto.generateKeyPairSync('rsa'",
			newLines: []string{
				"  // MIGRATION: Replace RSA with Post-Quantum Cryptography",
				"  // Consider using liboqs-node or crystals-kyber npm package",
				"  // Hybrid approach: use ML-KEM for key encapsulation alongside RSA during transition",
				"  // const { publicKey, privateKey } = kyber.keypair();",
			},
			description: "Replace RSA key generation with PQC migration path",
			confidence:  0.7,
		},
		{
			oldContains: "crypto.createHash('md5')",
			newLines:    []string{"  crypto.createHash('sha256')"},
			description: "Replace MD5 with SHA-256",
			confidence:  0.95,
		},
		{
			oldContains: "crypto.createHash('sha1')",
			newLines:    []string{"  crypto.createHash('sha256')"},
			description: "Replace SHA-1 with SHA-256",
			confidence:  0.95,
		},
	}
}

// javaStrategies returns fix strategies for Java code.
func javaStrategies() []fixStrategy {
	return []fixStrategy{
		{
			oldContains: "KeyPairGenerator.getInstance(\"RSA\")",
			newLines: []string{
				"        // MIGRATION: Replace RSA with ML-KEM (Post-Quantum)",
				"        // Use Bouncy Castle PQC provider: bcprov-lts8on",
				"        // KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"ML-KEM\", \"BCPQC\");",
				"        // kpg.initialize(MLKEMParameterSpec.ml_kem_768);",
			},
			description: "Replace RSA key generation with ML-KEM post-quantum key encapsulation",
			confidence:  0.7,
		},
		{
			oldContains: "MessageDigest.getInstance(\"MD5\")",
			newLines:    []string{"        MessageDigest.getInstance(\"SHA-256\")"},
			description: "Replace MD5 with SHA-256",
			confidence:  0.95,
		},
		{
			oldContains: "MessageDigest.getInstance(\"SHA-1\")",
			newLines:    []string{"        MessageDigest.getInstance(\"SHA-256\")"},
			description: "Replace SHA-1 with SHA-256",
			confidence:  0.95,
		},
	}
}

// strategiesForLanguage returns applicable fix strategies for a language.
func strategiesForLanguage(lang string) []fixStrategy {
	switch strings.ToLower(lang) {
	case "go":
		return goStrategies()
	case "python":
		return pythonStrategies()
	case "javascript":
		return javascriptStrategies()
	case "java":
		return javaStrategies()
	default:
		return nil
	}
}

// GenerateFix produces a fix for a single finding.
// Returns nil if no auto-fix is available for this finding type.
func (fg *FixGenerator) GenerateFix(finding models.Finding, sourceLines []string) *FixResult {
	strategies := strategiesForLanguage(finding.Language)
	if strategies == nil {
		return nil
	}

	// Determine which line to fix. LineStart is 1-based.
	lineIdx := finding.LineStart - 1
	if lineIdx < 0 || lineIdx >= len(sourceLines) {
		return nil
	}

	sourceLine := sourceLines[lineIdx]

	for _, strat := range strategies {
		if !strings.Contains(sourceLine, strat.oldContains) {
			continue
		}

		// Build the replacement text by preserving the leading whitespace
		// of the original line for single-line replacements, or use
		// the strategy's own indentation for multi-line replacements.
		replacement := strings.Join(strat.newLines, "\n")

		diff := buildUnifiedDiff(finding.FilePath, sourceLines, lineIdx, strat.newLines)

		return &FixResult{
			FindingID:   finding.ID,
			FilePath:    finding.FilePath,
			Language:    finding.Language,
			Algorithm:   finding.Algorithm,
			Replacement: replacement,
			Diff:        diff,
			Description: strat.description,
			Confidence:  strat.confidence,
		}
	}

	// Check for TLS version fix via pattern in the line for Go
	if strings.ToLower(finding.Language) == "go" && strings.Contains(sourceLine, "tls.VersionTLS12") {
		newLine := strings.Replace(sourceLine, "tls.VersionTLS12", "tls.VersionTLS13", 1)
		diff := buildUnifiedDiff(finding.FilePath, sourceLines, lineIdx, []string{newLine})
		return &FixResult{
			FindingID:   finding.ID,
			FilePath:    finding.FilePath,
			Language:    finding.Language,
			Algorithm:   finding.Algorithm,
			Replacement: newLine,
			Diff:        diff,
			Description: "Upgrade minimum TLS version from 1.2 to 1.3",
			Confidence:  0.95,
		}
	}

	return nil
}

// GenerateAll produces fixes for all fixable findings.
func (fg *FixGenerator) GenerateAll(findings []models.Finding, readFile func(path string) ([]string, error)) []FixResult {
	var results []FixResult

	// Cache file contents to avoid re-reading
	fileCache := make(map[string][]string)

	for _, finding := range findings {
		lines, ok := fileCache[finding.FilePath]
		if !ok {
			var err error
			lines, err = readFile(finding.FilePath)
			if err != nil {
				continue
			}
			fileCache[finding.FilePath] = lines
		}

		fix := fg.GenerateFix(finding, lines)
		if fix != nil {
			results = append(results, *fix)
		}
	}

	return results
}

// buildUnifiedDiff creates a unified diff for a single-line replacement.
func buildUnifiedDiff(filePath string, sourceLines []string, targetIdx int, newLines []string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("--- a/%s\n", filePath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", filePath))

	// Calculate context boundaries (3 lines of context)
	contextLines := 3
	startCtx := targetIdx - contextLines
	if startCtx < 0 {
		startCtx = 0
	}
	endCtx := targetIdx + contextLines + 1
	if endCtx > len(sourceLines) {
		endCtx = len(sourceLines)
	}

	oldCount := endCtx - startCtx
	newCount := oldCount - 1 + len(newLines)

	// Hunk header (1-based line numbers)
	b.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", startCtx+1, oldCount, startCtx+1, newCount))

	// Leading context
	for i := startCtx; i < targetIdx; i++ {
		b.WriteString(fmt.Sprintf(" %s\n", sourceLines[i]))
	}

	// Removed line
	b.WriteString(fmt.Sprintf("-%s\n", sourceLines[targetIdx]))

	// Added lines
	for _, nl := range newLines {
		b.WriteString(fmt.Sprintf("+%s\n", nl))
	}

	// Trailing context
	for i := targetIdx + 1; i < endCtx; i++ {
		b.WriteString(fmt.Sprintf(" %s\n", sourceLines[i]))
	}

	return b.String()
}
