package pyast

import (
	"os"
	"path/filepath"
	"testing"

	"quantumshield/pkg/models"
)

func writeTempPy(t *testing.T, code string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.py")
	if err := os.WriteFile(p, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func requireAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a := New()
	if a == nil {
		t.Skip("python3 not available")
	}
	return a
}

func TestAnalyzeFile_RSAGeneration(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for RSA generation")
	}
	f := findings[0]
	if f.Algorithm != "RSA-2048" {
		t.Errorf("expected algorithm RSA-2048, got %s", f.Algorithm)
	}
	if f.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", f.KeySize)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %s", f.Severity)
	}
	if f.QuantumThreat != models.ThreatBrokenByShor {
		t.Errorf("expected quantum threat Shor, got %s", f.QuantumThreat)
	}
	if f.RuleID != "QS-PY-RSA-001" {
		t.Errorf("expected rule QS-PY-RSA-001, got %s", f.RuleID)
	}
}

func TestAnalyzeFile_ECDSA(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for ECDSA")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "QS-PY-ECDSA-001" {
			found = true
			if f.Algorithm != "ECDSA-P256" {
				t.Errorf("expected algorithm ECDSA-P256, got %s", f.Algorithm)
			}
			if f.Category != models.CategoryDigitalSignature {
				t.Errorf("expected category Digital Signature, got %s", f.Category)
			}
		}
	}
	if !found {
		t.Error("did not find ECDSA finding with rule QS-PY-ECDSA-001")
	}
}

func TestAnalyzeFile_HashlibMD5(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
import hashlib

digest = hashlib.md5(b"hello world")
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for hashlib.md5")
	}
	f := findings[0]
	if f.Algorithm != "MD5" {
		t.Errorf("expected algorithm MD5, got %s", f.Algorithm)
	}
	if f.RuleID != "QS-PY-MD5-001" {
		t.Errorf("expected rule QS-PY-MD5-001, got %s", f.RuleID)
	}
	if f.Category != models.CategoryHashing {
		t.Errorf("expected category Hashing, got %s", f.Category)
	}
}

func TestAnalyzeFile_Fernet(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "QS-PY-FERNET-001" {
			found = true
			if f.Severity != models.SeverityMedium {
				t.Errorf("expected severity MEDIUM, got %s", f.Severity)
			}
			if f.Category != models.CategorySymmetricEncryption {
				t.Errorf("expected category Symmetric Encryption, got %s", f.Category)
			}
			if f.ReplacementAlgo != "AES-256-GCM" {
				t.Errorf("expected replacement AES-256-GCM, got %s", f.ReplacementAlgo)
			}
		}
	}
	if !found {
		t.Error("did not find Fernet finding with rule QS-PY-FERNET-001")
	}
}

func TestAnalyzeFile_CleanCode(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
import os
import sys

def main():
    print("Hello, world!")
    x = 42
    return x

if __name__ == "__main__":
    main()
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean code, got %d: %+v", len(findings), findings)
	}
}

func TestAnalyzeFile_VariableResolution(t *testing.T) {
	a := requireAnalyzer(t)
	path := writeTempPy(t, `
import hashlib

algo = "md5"
digest = hashlib.new(algo)
`)
	findings, err := a.AnalyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for variable-resolved MD5")
	}
	f := findings[0]
	if f.RuleID != "QS-PY-TAINT-001" {
		t.Errorf("expected rule QS-PY-TAINT-001, got %s", f.RuleID)
	}
	if f.Algorithm != "MD5" {
		t.Errorf("expected algorithm MD5, got %s", f.Algorithm)
	}
	if f.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", f.Confidence)
	}
}
