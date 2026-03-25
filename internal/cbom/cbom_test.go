package cbom

import (
	"encoding/json"
	"strings"
	"testing"

	"quantumshield/pkg/models"
)

func rsaFinding() models.Finding {
	return models.Finding{
		ID:              "f-001",
		RuleID:          "QS-RSA-001",
		Severity:        models.SeverityCritical,
		Category:        models.CategoryAsymmetricEncryption,
		QuantumThreat:   models.ThreatBrokenByShor,
		FilePath:        "crypto/rsa.go",
		LineStart:       42,
		Algorithm:       "RSA-2048",
		KeySize:         2048,
		Language:        "go",
		ReplacementAlgo: "ML-KEM-768",
	}
}

func ecdsaFinding() models.Finding {
	return models.Finding{
		ID:              "f-002",
		RuleID:          "QS-ECDSA-001",
		Severity:        models.SeverityHigh,
		Category:        models.CategoryDigitalSignature,
		QuantumThreat:   models.ThreatBrokenByShor,
		FilePath:        "auth/sign.go",
		LineStart:       15,
		Algorithm:       "ECDSA-P256",
		Language:        "go",
		ReplacementAlgo: "ML-DSA-65",
	}
}

func md5Finding() models.Finding {
	return models.Finding{
		ID:            "f-003",
		RuleID:        "QS-MD5-001",
		Severity:      models.SeverityMedium,
		Category:      models.CategoryHashing,
		QuantumThreat: models.ThreatNotDirectlyThreatened,
		FilePath:      "util/hash.go",
		LineStart:     8,
		Algorithm:     "MD5",
		Language:      "go",
	}
}

func TestGenerate_RSAFinding(t *testing.T) {
	gen := NewGenerator("test-project", "1.0.0")
	bom := gen.Generate([]models.Finding{rsaFinding()})

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOMFormat CycloneDX, got %s", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.6" {
		t.Errorf("expected SpecVersion 1.6, got %s", bom.SpecVersion)
	}
	if bom.Version != 1 {
		t.Errorf("expected Version 1, got %d", bom.Version)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:qs-") {
		t.Errorf("expected serial number prefix urn:uuid:qs-, got %s", bom.SerialNumber)
	}

	// Metadata checks
	if bom.Metadata.Component == nil {
		t.Fatal("expected metadata component to be set")
	}
	if bom.Metadata.Component.Name != "test-project" {
		t.Errorf("expected project name test-project, got %s", bom.Metadata.Component.Name)
	}
	if len(bom.Metadata.Tools) != 1 || bom.Metadata.Tools[0].Name != "QuantumShield" {
		t.Error("expected QuantumShield tool in metadata")
	}

	// Component checks
	if len(bom.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(bom.Components))
	}
	comp := bom.Components[0]
	if comp.Type != "cryptographic-asset" {
		t.Errorf("expected type cryptographic-asset, got %s", comp.Type)
	}
	if comp.Name != "RSA-2048" {
		t.Errorf("expected name RSA-2048, got %s", comp.Name)
	}
	if comp.CryptoProperties == nil {
		t.Fatal("expected cryptoProperties to be set")
	}
	if comp.CryptoProperties.AssetType != "algorithm" {
		t.Errorf("expected assetType algorithm, got %s", comp.CryptoProperties.AssetType)
	}
	if comp.CryptoProperties.OID != "1.2.840.113549.1.1.1" {
		t.Errorf("expected RSA OID, got %s", comp.CryptoProperties.OID)
	}
	ap := comp.CryptoProperties.AlgorithmProperties
	if ap == nil {
		t.Fatal("expected algorithmProperties to be set")
	}
	if ap.Primitive != "pke" {
		t.Errorf("expected primitive pke, got %s", ap.Primitive)
	}
	if ap.ParameterSetIdentifier != "2048" {
		t.Errorf("expected parameterSetIdentifier 2048, got %s", ap.ParameterSetIdentifier)
	}
	if ap.QuantumSecurityLevel != 0 {
		t.Errorf("expected quantumSecurityLevel 0 for RSA, got %d", ap.QuantumSecurityLevel)
	}

	// Evidence
	if comp.Evidence == nil || len(comp.Evidence.Occurrences) != 1 {
		t.Fatal("expected 1 occurrence in evidence")
	}
	if comp.Evidence.Occurrences[0].Location != "crypto/rsa.go:42" {
		t.Errorf("expected location crypto/rsa.go:42, got %s", comp.Evidence.Occurrences[0].Location)
	}

	// Vulnerability
	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(bom.Vulnerabilities))
	}
	vuln := bom.Vulnerabilities[0]
	if vuln.ID != "QS-RSA-001" {
		t.Errorf("expected vulnerability ID QS-RSA-001, got %s", vuln.ID)
	}
	if !strings.Contains(vuln.Description, "RSA-2048") {
		t.Errorf("expected description to mention RSA-2048, got %s", vuln.Description)
	}
	if !strings.Contains(vuln.Recommendation, "ML-KEM-768") {
		t.Errorf("expected recommendation to mention ML-KEM-768, got %s", vuln.Recommendation)
	}
}

func TestGenerate_MultipleAlgorithms(t *testing.T) {
	gen := NewGenerator("multi-project", "2.0.0")
	findings := []models.Finding{rsaFinding(), ecdsaFinding(), md5Finding()}
	bom := gen.Generate(findings)

	if len(bom.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(bom.Components))
	}

	// RSA and ECDSA are ThreatBrokenByShor, MD5 is not
	if len(bom.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities (RSA + ECDSA), got %d", len(bom.Vulnerabilities))
	}

	// Verify each algorithm produced a component
	names := make(map[string]bool)
	for _, c := range bom.Components {
		names[c.Name] = true
	}
	for _, expected := range []string{"RSA-2048", "ECDSA-P256", "MD5"} {
		if !names[expected] {
			t.Errorf("expected component %s not found", expected)
		}
	}
}

func TestToJSON(t *testing.T) {
	gen := NewGenerator("json-project", "1.0.0")
	bom := gen.Generate([]models.Finding{rsaFinding()})
	data, err := gen.ToJSON(bom)
	if err != nil {
		t.Fatalf("ToJSON returned error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify key fields
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX in JSON")
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("expected specVersion 1.6 in JSON")
	}
}

func TestToCSV(t *testing.T) {
	gen := NewGenerator("csv-project", "1.0.0")
	bom := gen.Generate([]models.Finding{rsaFinding()})
	csv := gen.ToCSV(bom)

	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least header + 1 data row, got %d lines", len(lines))
	}

	// Check header
	expectedHeader := "Algorithm,Type,Primitive,KeySize,ClassicalBits,QuantumBits,OID,Occurrences,QuantumVulnerable"
	if lines[0] != expectedHeader {
		t.Errorf("unexpected header:\n  got:  %s\n  want: %s", lines[0], expectedHeader)
	}

	// Check data row contains RSA info
	if !strings.Contains(lines[1], "RSA-2048") {
		t.Errorf("expected data row to contain RSA-2048, got %s", lines[1])
	}
	if !strings.Contains(lines[1], "pke") {
		t.Errorf("expected data row to contain primitive pke, got %s", lines[1])
	}
	if !strings.Contains(lines[1], "true") {
		t.Errorf("expected QuantumVulnerable=true for RSA, got %s", lines[1])
	}
}

func TestOID(t *testing.T) {
	tests := []struct {
		algo string
		oid  string
	}{
		{"RSA-2048", "1.2.840.113549.1.1.1"},
		{"ECDSA-P256", "1.2.840.10045.2.1"},
		{"AES-128-GCM", "2.16.840.1.101.3.4.1.6"},
		{"AES-256-GCM", "2.16.840.1.101.3.4.1.46"},
		{"MD5", "1.2.840.113549.2.5"},
		{"SHA-1", "1.3.14.3.2.26"},
		{"3DES", "1.2.840.113549.3.7"},
		{"UnknownAlgo", ""},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := getOID(tt.algo)
			if got != tt.oid {
				t.Errorf("getOID(%s) = %s, want %s", tt.algo, got, tt.oid)
			}
		})
	}
}

func TestAlgoProperties(t *testing.T) {
	tests := []struct {
		name             string
		algo             string
		finding          models.Finding
		expectedPrim     string
		expectedClassical int
		expectedQuantum  int
	}{
		{
			name:             "RSA",
			algo:             "RSA-2048",
			finding:          rsaFinding(),
			expectedPrim:     "pke",
			expectedClassical: 112,
			expectedQuantum:  0,
		},
		{
			name:             "ECDSA-P256",
			algo:             "ECDSA-P256",
			finding:          ecdsaFinding(),
			expectedPrim:     "sig",
			expectedClassical: 128,
			expectedQuantum:  0,
		},
		{
			name:             "MD5",
			algo:             "MD5",
			finding:          md5Finding(),
			expectedPrim:     "hash",
			expectedClassical: 0,
			expectedQuantum:  0,
		},
		{
			name: "AES-256",
			algo: "AES-256-GCM",
			finding: models.Finding{
				Algorithm: "AES-256-GCM",
				Language:  "go",
			},
			expectedPrim:     "ae",
			expectedClassical: 256,
			expectedQuantum:  128,
		},
		{
			name: "AES-128",
			algo: "AES-128-CBC",
			finding: models.Finding{
				Algorithm: "AES-128-CBC",
				Language:  "go",
			},
			expectedPrim:     "ae",
			expectedClassical: 128,
			expectedQuantum:  64,
		},
		{
			name: "DES",
			algo: "DES",
			finding: models.Finding{
				Algorithm: "DES",
				Language:  "java",
			},
			expectedPrim:     "ae",
			expectedClassical: 56,
			expectedQuantum:  0,
		},
		{
			name: "3DES",
			algo: "3DES",
			finding: models.Finding{
				Algorithm: "3DES",
				Language:  "java",
			},
			expectedPrim:     "ae",
			expectedClassical: 112,
			expectedQuantum:  0,
		},
		{
			name: "SHA-1",
			algo: "SHA-1",
			finding: models.Finding{
				Algorithm: "SHA-1",
				Language:  "python",
			},
			expectedPrim:     "hash",
			expectedClassical: 0,
			expectedQuantum:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := buildAlgoProperties(tt.algo, []models.Finding{tt.finding})
			if ap.Primitive != tt.expectedPrim {
				t.Errorf("primitive = %s, want %s", ap.Primitive, tt.expectedPrim)
			}
			if ap.ClassicalSecurityLevel != tt.expectedClassical {
				t.Errorf("classicalSecurityLevel = %d, want %d", ap.ClassicalSecurityLevel, tt.expectedClassical)
			}
			if ap.QuantumSecurityLevel != tt.expectedQuantum {
				t.Errorf("quantumSecurityLevel = %d, want %d", ap.QuantumSecurityLevel, tt.expectedQuantum)
			}
		})
	}
}

func TestGenerate_EmptyFindings(t *testing.T) {
	gen := NewGenerator("empty-project", "1.0.0")
	bom := gen.Generate([]models.Finding{})

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOMFormat CycloneDX, got %s", bom.BOMFormat)
	}
	if len(bom.Components) != 0 {
		t.Errorf("expected 0 components for empty findings, got %d", len(bom.Components))
	}
	if len(bom.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for empty findings, got %d", len(bom.Vulnerabilities))
	}
	if bom.Metadata.Component.Name != "empty-project" {
		t.Errorf("expected project name empty-project, got %s", bom.Metadata.Component.Name)
	}
}
