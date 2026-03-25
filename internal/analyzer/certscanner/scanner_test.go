package certscanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quantumshield/pkg/models"
)

// ---------------------------------------------------------------------------
// Helpers — generate self-signed certificates for testing
// ---------------------------------------------------------------------------

func generateRSACertPEM(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-rsa.example.com",
			Organization: []string{"QuantumShield Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // ~10 years → after 2030
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test-rsa.example.com", "*.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func generateECDSACertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test-ecdsa.example.com",
			Organization: []string{"QuantumShield Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

// writeTempFile writes data to a file inside a temporary directory and returns
// the path. The directory is automatically cleaned up when the test finishes.
func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestScanFile_RSACert(t *testing.T) {
	pemData := generateRSACertPEM(t, 2048)
	path := writeTempFile(t, "server.crt", pemData)

	scanner := NewCertScanner()
	findings, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for RSA-2048 certificate")
	}

	// Find the public-key finding.
	var found *models.Finding
	for i := range findings {
		if findings[i].RuleID == "CERT-PQC-001" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected CERT-PQC-001 finding")
	}

	if found.Severity != models.SeverityCritical {
		t.Errorf("severity: got %v, want CRITICAL", found.Severity)
	}
	if found.QuantumThreat != models.ThreatBrokenByShor {
		t.Errorf("quantum threat: got %v, want BrokenByShor", found.QuantumThreat)
	}
	if found.Category != models.CategoryCertificate {
		t.Errorf("category: got %v, want Certificate", found.Category)
	}
	if found.Algorithm != "RSA-2048" {
		t.Errorf("algorithm: got %q, want RSA-2048", found.Algorithm)
	}
	if found.KeySize != 2048 {
		t.Errorf("key size: got %d, want 2048", found.KeySize)
	}
	if !strings.Contains(found.Description, "test-rsa.example.com") {
		t.Errorf("description should contain subject, got: %s", found.Description)
	}
	if !strings.Contains(found.Description, "after 2030") {
		t.Errorf("description should warn about post-2030 expiry, got: %s", found.Description)
	}
	if found.ReplacementAlgo == "" {
		t.Error("replacement algo should not be empty")
	}
}

func TestScanFile_ECDSACert(t *testing.T) {
	pemData := generateECDSACertPEM(t)
	path := writeTempFile(t, "ec.pem", pemData)

	scanner := NewCertScanner()
	findings, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for ECDSA P-256 certificate")
	}

	var found *models.Finding
	for i := range findings {
		if findings[i].RuleID == "CERT-PQC-001" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected CERT-PQC-001 finding")
	}

	if found.Severity != models.SeverityCritical {
		t.Errorf("severity: got %v, want CRITICAL", found.Severity)
	}
	if found.QuantumThreat != models.ThreatBrokenByShor {
		t.Errorf("quantum threat: got %v, want BrokenByShor", found.QuantumThreat)
	}
	if found.Algorithm != "ECDSA-P256" {
		t.Errorf("algorithm: got %q, want ECDSA-P256", found.Algorithm)
	}
	if found.KeySize != 256 {
		t.Errorf("key size: got %d, want 256", found.KeySize)
	}
	if !strings.Contains(found.Description, "test-ecdsa.example.com") {
		t.Errorf("description should contain subject, got: %s", found.Description)
	}
	if found.ReplacementAlgo == "" {
		t.Error("replacement algo should not be empty")
	}
}

func TestScanSource_EmbeddedPEM(t *testing.T) {
	// Generate a real cert and embed it in Go source code.
	certPEM := generateRSACertPEM(t, 2048)

	// Build source with the PEM block embedded verbatim (the PEM text
	// appears inside the file exactly as it would in a raw string literal).
	var buf strings.Builder
	buf.WriteString("package main\n\n// This file has an embedded certificate.\nvar caCert = `\n")
	buf.Write(certPEM)
	buf.WriteString("`\n\nfunc main() {}\n")
	goSource := []byte(buf.String())

	path := writeTempFile(t, "main.go", goSource)

	scanner := NewCertScanner()
	findings, err := scanner.ScanSource(path, goSource)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings for embedded PEM certificate in source")
	}

	f := findings[0]
	if f.Usage != "embedded certificate in source" {
		t.Errorf("usage: got %q, want 'embedded certificate in source'", f.Usage)
	}
	if f.FilePath != path {
		t.Errorf("file path: got %q, want %q", f.FilePath, path)
	}
}

func TestScanFile_NoCert(t *testing.T) {
	data := []byte("this is just a regular text file, nothing to see here\n")
	path := writeTempFile(t, "readme.txt", data)

	// Rename to .pem so the scanner will try to parse it.
	pemPath := filepath.Join(filepath.Dir(path), "notacert.pem")
	if err := os.Rename(path, pemPath); err != nil {
		t.Fatal(err)
	}

	scanner := NewCertScanner()
	findings, err := scanner.ScanFile(pemPath)
	// Should return an error since no valid cert was found.
	if err == nil && len(findings) > 0 {
		t.Error("expected no findings for non-certificate file")
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()

	// Write a cert file.
	pemData := generateRSACertPEM(t, 4096)
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), pemData, 0644); err != nil {
		t.Fatal(err)
	}

	// Write a source file with embedded cert.
	ecPEM := generateECDSACertPEM(t)
	var srcBuf strings.Builder
	srcBuf.WriteString("package tls\nvar cert = `\n")
	srcBuf.Write(ecPEM)
	srcBuf.WriteString("`\n")
	goSrc := []byte(srcBuf.String())
	if err := os.WriteFile(filepath.Join(dir, "certs.go"), goSrc, 0644); err != nil {
		t.Fatal(err)
	}

	// Write a plain text file (should be ignored).
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("nothing"), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewCertScanner()
	findings, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	// We expect at least one from ca.crt and one from certs.go.
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}
