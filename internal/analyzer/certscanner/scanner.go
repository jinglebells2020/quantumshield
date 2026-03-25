package certscanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// certExtensions lists file extensions treated as certificate files.
var certExtensions = map[string]bool{
	".pem": true,
	".crt": true,
	".cer": true,
	".der": true,
}

// sourceExtensions lists file extensions treated as source code that might
// embed PEM-encoded certificates.
var sourceExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".java": true,
	".rb":   true,
	".rs":   true,
	".c":    true,
	".cpp":  true,
	".h":    true,
	".cs":   true,
	".php":  true,
	".yaml": true,
	".yml":  true,
	".json": true,
	".toml": true,
	".xml":  true,
	".conf": true,
	".cfg":  true,
	".ini":  true,
	".tf":   true,
}

// quantumDeadline is the year after which quantum-vulnerable certificates
// represent an elevated risk.
var quantumDeadline = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// CertScanner finds and analyses X.509 certificates for quantum vulnerability.
type CertScanner struct{}

// NewCertScanner returns a ready-to-use scanner.
func NewCertScanner() *CertScanner {
	return &CertScanner{}
}

// ScanFile parses a PEM or DER encoded certificate file and returns findings.
func (cs *CertScanner) ScanFile(path string) ([]models.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certscanner: read %s: %w", path, err)
	}

	certs, err := parseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("certscanner: parse %s: %w", path, err)
	}

	var findings []models.Finding
	for _, cert := range certs {
		findings = append(findings, analyzeCert(cert, path)...)
	}
	return findings, nil
}

// ScanSource finds PEM blocks embedded in source code and analyses them.
func (cs *CertScanner) ScanSource(path string, content []byte) ([]models.Finding, error) {
	var findings []models.Finding

	// Walk through all PEM blocks in content.
	rest := content
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // skip unparseable blocks
		}
		ff := analyzeCert(cert, path)
		for i := range ff {
			ff[i].Usage = "embedded certificate in source"
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// ScanDirectory walks the directory tree rooted at root. Certificate files
// (.pem, .crt, .cer, .der) are fully parsed; source files are scanned for
// embedded PEM blocks.
func (cs *CertScanner) ScanDirectory(root string) ([]models.Finding, error) {
	var findings []models.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			base := filepath.Base(path)
			// Skip common non-interesting directories.
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		if certExtensions[ext] {
			ff, err := cs.ScanFile(path)
			if err == nil {
				findings = append(findings, ff...)
			}
			return nil
		}

		if sourceExtensions[ext] {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			// Quick check before expensive PEM decode.
			if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
				return nil
			}
			ff, err := cs.ScanSource(path, data)
			if err == nil {
				findings = append(findings, ff...)
			}
		}
		return nil
	})
	if err != nil {
		return findings, fmt.Errorf("certscanner: walk %s: %w", root, err)
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// parseCertificates tries PEM first, falls back to DER.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Try PEM decoding first.
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) > 0 {
		return certs, nil
	}

	// Fall back to raw DER.
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("no certificates found")
	}
	return []*x509.Certificate{cert}, nil
}

// analyzeCert produces findings for a single certificate.
func analyzeCert(cert *x509.Certificate, path string) []models.Finding {
	var findings []models.Finding

	algo, keySize := publicKeyInfo(cert)
	description := certDescription(cert, algo, keySize)

	// Public-key algorithm finding.
	if f, ok := publicKeyFinding(cert, algo, keySize, path, description); ok {
		findings = append(findings, f)
	}

	// Signature algorithm finding (SHA-1).
	if f, ok := signatureFinding(cert, path); ok {
		findings = append(findings, f)
	}

	return findings
}

// publicKeyInfo extracts the algorithm name and key size from a certificate.
func publicKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		return fmt.Sprintf("RSA-%d", bits), bits
	case *ecdsa.PublicKey:
		bits := pub.Params().BitSize
		return fmt.Sprintf("ECDSA-P%d", bits), bits
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// certDescription builds a human-readable description for a certificate
// finding.
func certDescription(cert *x509.Certificate, algo string, keySize int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "X.509 certificate using %s (%d-bit)", algo, keySize)
	if cert.Subject.CommonName != "" {
		fmt.Fprintf(&b, ", Subject: %s", cert.Subject.CommonName)
	}
	fmt.Fprintf(&b, ", Issuer: %s", cert.Issuer.CommonName)
	fmt.Fprintf(&b, ", Expires: %s", cert.NotAfter.Format("2006-01-02"))

	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(&b, ", SANs: %s", strings.Join(cert.DNSNames, ", "))
	}

	if cert.NotAfter.After(quantumDeadline) && isQuantumVulnerableAlgo(cert.PublicKeyAlgorithm) {
		b.WriteString(". WARNING: certificate expires after 2030 with quantum-vulnerable algorithm")
	}

	return b.String()
}

// isQuantumVulnerableAlgo returns true for algorithms broken by Shor's.
func isQuantumVulnerableAlgo(algo x509.PublicKeyAlgorithm) bool {
	switch algo {
	case x509.RSA, x509.ECDSA, x509.Ed25519:
		return true
	default:
		return false
	}
}

// publicKeyFinding creates a Finding for the certificate's public key
// algorithm if it is quantum-vulnerable.
func publicKeyFinding(cert *x509.Certificate, algo string, keySize int, path, description string) (models.Finding, bool) {
	var replacement string

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		replacement = "ML-KEM (CRYSTALS-Kyber) + ML-DSA (CRYSTALS-Dilithium)"
	case x509.ECDSA:
		replacement = "ML-DSA (CRYSTALS-Dilithium)"
	case x509.Ed25519:
		replacement = "ML-DSA (CRYSTALS-Dilithium)"
	default:
		return models.Finding{}, false
	}

	return models.Finding{
		RuleID:          "CERT-PQC-001",
		Severity:        models.SeverityCritical,
		Category:        models.CategoryCertificate,
		QuantumThreat:   models.ThreatBrokenByShor,
		FilePath:        path,
		Algorithm:       algo,
		KeySize:         keySize,
		Description:     description,
		ReplacementAlgo: replacement,
		RecommendedFix:  fmt.Sprintf("Replace %s certificate with post-quantum alternative (%s)", algo, replacement),
		MigrationEffort: migrationEffort(cert),
		Confidence:      1.0,
		CreatedAt:       time.Now(),
	}, true
}

// signatureFinding creates a Finding when the signature algorithm uses SHA-1.
func signatureFinding(cert *x509.Certificate, path string) (models.Finding, bool) {
	if !isSHA1Signature(cert.SignatureAlgorithm) {
		return models.Finding{}, false
	}

	return models.Finding{
		RuleID:          "CERT-HASH-001",
		Severity:        models.SeverityHigh,
		Category:        models.CategoryCertificate,
		QuantumThreat:   models.ThreatWeakenedByGrover,
		FilePath:        path,
		Algorithm:       cert.SignatureAlgorithm.String(),
		Description:     fmt.Sprintf("Certificate signed with SHA-1 (%s), weakened by Grover's algorithm. Subject: %s", cert.SignatureAlgorithm, cert.Subject.CommonName),
		ReplacementAlgo: "SHA-256 or SHA-384",
		RecommendedFix:  "Re-sign certificate with SHA-256 or SHA-384 based signature algorithm",
		MigrationEffort: "low",
		Confidence:      1.0,
		CreatedAt:       time.Now(),
	}, true
}

// isSHA1Signature returns true if the signature algorithm is SHA-1 based.
func isSHA1Signature(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// migrationEffort estimates migration effort based on the certificate.
func migrationEffort(cert *x509.Certificate) string {
	if cert.IsCA {
		return "high"
	}
	if len(cert.DNSNames) > 3 {
		return "medium"
	}
	return "low"
}
