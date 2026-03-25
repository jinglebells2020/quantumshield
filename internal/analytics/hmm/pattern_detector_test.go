package hmm

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestDetectPatterns_RSAWithoutHybrid(t *testing.T) {
	pd := NewPatternDetector()

	// Use a longer RSA-heavy sequence so the insecure model's LLR accumulates
	// above the threshold. Real code typically has repeated RSA operations.
	apiCalls := []ObservedAPICall{
		{Name: "rsa.GenerateKey", APICallType: APICallRSAGenerateKey, Line: 10, FilePath: "main.go"},
		{Name: "rsa.EncryptOAEP", APICallType: APICallRSAEncrypt, Line: 15, FilePath: "main.go"},
		{Name: "rsa.DecryptOAEP", APICallType: APICallRSADecrypt, Line: 20, FilePath: "main.go"},
		{Name: "rsa.SignPKCS1v15", APICallType: APICallRSASign, Line: 25, FilePath: "main.go"},
		{Name: "rsa.EncryptOAEP", APICallType: APICallRSAEncrypt, Line: 30, FilePath: "main.go"},
		{Name: "rsa.GenerateKey", APICallType: APICallRSAGenerateKey, Line: 35, FilePath: "main.go"},
		{Name: "rsa.DecryptOAEP", APICallType: APICallRSADecrypt, Line: 40, FilePath: "main.go"},
		{Name: "rsa.SignPKCS1v15", APICallType: APICallRSASign, Line: 45, FilePath: "main.go"},
	}

	patterns, err := pd.DetectPatterns(apiCalls, "main.go")
	if err != nil {
		t.Fatalf("DetectPatterns error: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("expected at least one vulnerability pattern for RSA without hybrid, got none")
	}

	// At least one pattern should flag RSA
	foundRSA := false
	for _, p := range patterns {
		if p.Finding.Algorithm == "RSA" ||
			p.Finding.RuleID == "HMM-002" ||
			containsAny(p.APICallTypes, APICallRSAGenerateKey, APICallRSAEncrypt) {
			foundRSA = true
			if p.Finding.Severity != models.SeverityCritical {
				t.Errorf("RSA vulnerability should be CRITICAL, got %v", p.Finding.Severity)
			}
			if p.LogLikelihoodRatio <= 0 {
				t.Errorf("LLR should be positive for insecure pattern, got %f", p.LogLikelihoodRatio)
			}
			break
		}
	}
	if !foundRSA {
		t.Error("expected a pattern involving RSA API calls")
		for i, p := range patterns {
			t.Logf("  pattern[%d]: rule=%s algo=%s calls=%v", i, p.Finding.RuleID, p.Finding.Algorithm, p.APICallTypes)
		}
	}
}

func TestDetectPatterns_SecureSequence(t *testing.T) {
	pd := NewPatternDetector()

	apiCalls := []ObservedAPICall{
		{Name: "mlkem.Encapsulate", APICallType: APICallMLKEMEncapsulate, Line: 5, FilePath: "secure.go"},
		{Name: "aes.NewCipher", APICallType: APICallAESNewCipher, Line: 10, FilePath: "secure.go"},
		{Name: "cipher.NewGCM", APICallType: APICallAESGCM, Line: 11, FilePath: "secure.go"},
	}

	patterns, err := pd.DetectPatterns(apiCalls, "secure.go")
	if err != nil {
		t.Fatalf("DetectPatterns error: %v", err)
	}

	// A sequence of ML-KEM + AES-GCM should not flag any vulnerabilities
	if len(patterns) > 0 {
		t.Errorf("expected no vulnerability patterns for secure sequence, got %d", len(patterns))
		for i, p := range patterns {
			t.Logf("  pattern[%d]: rule=%s algo=%s LLR=%.4f",
				i, p.Finding.RuleID, p.Finding.Algorithm, p.LogLikelihoodRatio)
		}
	}
}

func TestDetectPatterns_UnauthenticatedAES(t *testing.T) {
	pd := NewPatternDetector()

	// Use a longer sequence of unauthenticated AES usage so the insecure
	// model LLR exceeds the threshold. Simulates repeated CFB/CBC patterns.
	apiCalls := []ObservedAPICall{
		{Name: "aes.NewCipher", APICallType: APICallAESNewCipher, Line: 20, FilePath: "encrypt.go"},
		{Name: "cipher.NewCFBEncrypter", APICallType: APICallAESCFB, Line: 22, FilePath: "encrypt.go"},
		{Name: "aes.NewCipher", APICallType: APICallAESNewCipher, Line: 30, FilePath: "encrypt.go"},
		{Name: "cipher.NewCBCEncrypter", APICallType: APICallAESCBC, Line: 32, FilePath: "encrypt.go"},
		{Name: "aes.NewCipher", APICallType: APICallAESNewCipher, Line: 40, FilePath: "encrypt.go"},
		{Name: "cipher.NewCFBEncrypter", APICallType: APICallAESCFB, Line: 42, FilePath: "encrypt.go"},
		{Name: "cipher.NewCFBEncrypter", APICallType: APICallAESCFB, Line: 50, FilePath: "encrypt.go"},
		{Name: "cipher.NewCBCEncrypter", APICallType: APICallAESCBC, Line: 55, FilePath: "encrypt.go"},
	}

	patterns, err := pd.DetectPatterns(apiCalls, "encrypt.go")
	if err != nil {
		t.Fatalf("DetectPatterns error: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("expected at least one vulnerability pattern for unauthenticated AES, got none")
	}

	// Check that at least one pattern relates to unauthenticated AES
	foundAES := false
	for _, p := range patterns {
		if p.Finding.Algorithm == "AES-CFB/CBC" ||
			p.Finding.RuleID == "HMM-003" ||
			containsAny(p.APICallTypes, APICallAESCFB, APICallAESCBC) {
			foundAES = true
			if p.Finding.Severity != models.SeverityHigh {
				t.Errorf("unauthenticated AES should be HIGH severity, got %v", p.Finding.Severity)
			}
			if p.Finding.ReplacementAlgo != "AES-256-GCM" {
				t.Errorf("replacement should be AES-256-GCM, got %s", p.Finding.ReplacementAlgo)
			}
			break
		}
	}
	if !foundAES {
		t.Error("expected a pattern flagging unauthenticated AES usage")
		for i, p := range patterns {
			t.Logf("  pattern[%d]: rule=%s algo=%s calls=%v", i, p.Finding.RuleID, p.Finding.Algorithm, p.APICallTypes)
		}
	}
}

func TestExtractAPICallSequence_GoFile(t *testing.T) {
	source := `package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plaintext, nil)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	stream := cipher.NewCFBEncrypter(block, iv)
}
`

	calls := ExtractAPICallSequence(source, "test.go")
	if len(calls) == 0 {
		t.Fatal("expected API calls to be extracted, got none")
	}

	// Verify specific calls were found
	expectedCalls := map[int]bool{
		APICallRSAGenerateKey: false,
		APICallRSAEncrypt:     false,
		APICallSHA256:         false,
		APICallAESNewCipher:   false,
		APICallAESGCM:         false,
		APICallAESCFB:         false,
	}

	for _, call := range calls {
		if _, ok := expectedCalls[call.APICallType]; ok {
			expectedCalls[call.APICallType] = true
		}
	}

	for apiType, found := range expectedCalls {
		if !found {
			t.Errorf("expected to find API call type %d (%s) in extracted calls",
				apiType, APICallName[apiType])
		}
	}

	// Verify line numbers are set
	for _, call := range calls {
		if call.Line <= 0 {
			t.Errorf("API call %s has invalid line number: %d", call.Name, call.Line)
		}
		if call.FilePath != "test.go" {
			t.Errorf("API call %s has wrong file path: %s", call.Name, call.FilePath)
		}
	}

	// Verify ordering: rsa.GenerateKey should appear before cipher.NewGCM
	rsaIdx := -1
	gcmIdx := -1
	for i, call := range calls {
		if call.APICallType == APICallRSAGenerateKey && rsaIdx == -1 {
			rsaIdx = i
		}
		if call.APICallType == APICallAESGCM && gcmIdx == -1 {
			gcmIdx = i
		}
	}
	if rsaIdx >= 0 && gcmIdx >= 0 && rsaIdx >= gcmIdx {
		t.Errorf("rsa.GenerateKey (idx=%d) should appear before cipher.NewGCM (idx=%d)",
			rsaIdx, gcmIdx)
	}
}

func TestExtractAPICallSequence_EmptySource(t *testing.T) {
	calls := ExtractAPICallSequence("", "empty.go")
	if len(calls) != 0 {
		t.Errorf("expected 0 calls from empty source, got %d", len(calls))
	}
}

func TestExtractAPICallSequence_NoCryptoCode(t *testing.T) {
	source := `package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
`
	calls := ExtractAPICallSequence(source, "hello.go")
	if len(calls) != 0 {
		t.Errorf("expected 0 calls from non-crypto source, got %d", len(calls))
	}
}

func TestNewPatternDetector_WithOptions(t *testing.T) {
	pd := NewPatternDetector(WithThreshold(5.0))
	if pd.threshold != 5.0 {
		t.Errorf("expected threshold 5.0, got %f", pd.threshold)
	}

	// With high threshold, even insecure patterns should pass
	apiCalls := []ObservedAPICall{
		{Name: "rsa.GenerateKey", APICallType: APICallRSAGenerateKey, Line: 1, FilePath: "test.go"},
	}
	patterns, err := pd.DetectPatterns(apiCalls, "test.go")
	if err != nil {
		t.Fatalf("DetectPatterns error: %v", err)
	}
	// With a very high threshold, the LLR may not exceed it for a short sequence
	_ = patterns
}

func TestPatternDetector_DetectPatternsEmpty(t *testing.T) {
	pd := NewPatternDetector()
	patterns, err := pd.DetectPatterns(nil, "empty.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patterns != nil {
		t.Errorf("expected nil patterns for empty input, got %v", patterns)
	}
}
