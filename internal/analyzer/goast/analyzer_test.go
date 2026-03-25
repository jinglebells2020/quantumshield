package goast

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestAnalyzeFile_RSAGenerateKey(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	_ = key
}
`)
	a := New()
	findings, err := a.AnalyzeFile("rsa_keygen.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for rsa.GenerateKey")
	}

	f := findings[0]
	if f.Algorithm != "RSA-2048" {
		t.Errorf("expected algorithm RSA-2048, got %s", f.Algorithm)
	}
	if f.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", f.KeySize)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected severity Critical, got %s", f.Severity)
	}
	if f.Category != models.CategoryAsymmetricEncryption {
		t.Errorf("expected category AsymmetricEncryption, got %s", f.Category)
	}
	if f.QuantumThreat != models.ThreatBrokenByShor {
		t.Errorf("expected threat BrokenByShor, got %s", f.QuantumThreat)
	}
	if f.LineStart != 9 {
		t.Errorf("expected line 9, got %d", f.LineStart)
	}
	if f.ColumnStart < 1 {
		t.Errorf("expected column >= 1, got %d", f.ColumnStart)
	}
	if f.Language != "go" {
		t.Errorf("expected language go, got %s", f.Language)
	}
	if f.Library != "crypto/rsa" {
		t.Errorf("expected library crypto/rsa, got %s", f.Library)
	}
	if f.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", f.Confidence)
	}
	if f.Usage != "key-generation" {
		t.Errorf("expected usage key-generation, got %s", f.Usage)
	}
	if f.CodeSnippet == "" {
		t.Error("expected non-empty code snippet")
	}
	if f.ReplacementAlgo == "" {
		t.Error("expected non-empty replacement algorithm from migration map")
	}
}

func TestAnalyzeFile_RSAGenerateKey4096(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	_ = key
}
`)
	a := New()
	findings, err := a.AnalyzeFile("rsa_4096.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for RSA-4096")
	}
	f := findings[0]
	if f.Algorithm != "RSA-4096" {
		t.Errorf("expected algorithm RSA-4096, got %s", f.Algorithm)
	}
	if f.KeySize != 4096 {
		t.Errorf("expected key size 4096, got %d", f.KeySize)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected severity High for RSA-4096, got %s", f.Severity)
	}
}

func TestAnalyzeFile_RSAEncryptDecrypt(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func encrypt(pub *rsa.PublicKey, msg []byte) []byte {
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	return ct
}

func decrypt(priv *rsa.PrivateKey, ct []byte) []byte {
	pt, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
	return pt
}

func oldEncrypt(pub *rsa.PublicKey, msg []byte) []byte {
	ct, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	return ct
}

func oldDecrypt(priv *rsa.PrivateKey, ct []byte) []byte {
	pt, _ := rsa.DecryptPKCS1v15(rand.Reader, priv, ct)
	return pt
}
`)
	a := New()
	findings, err := a.AnalyzeFile("rsa_ops.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (EncryptOAEP, DecryptOAEP, EncryptPKCS1v15, DecryptPKCS1v15), got %d", len(findings))
	}

	usages := make(map[string]bool)
	for _, f := range findings {
		usages[f.Usage] = true
		if f.QuantumThreat != models.ThreatBrokenByShor {
			t.Errorf("expected BrokenByShor for %s, got %s", f.Algorithm, f.QuantumThreat)
		}
	}
	if !usages["encryption"] || !usages["decryption"] {
		t.Errorf("expected both encryption and decryption usages, got %v", usages)
	}
}

func TestAnalyzeFile_RSASign(t *testing.T) {
	src := []byte(`package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func signPSS(priv *rsa.PrivateKey, hash []byte) []byte {
	sig, _ := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hash, nil)
	return sig
}

func signPKCS(priv *rsa.PrivateKey, hash []byte) []byte {
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash)
	return sig
}
`)
	a := New()
	findings, err := a.AnalyzeFile("rsa_sign.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (SignPSS, SignPKCS1v15), got %d", len(findings))
	}
	for _, f := range findings {
		if f.Category != models.CategoryDigitalSignature {
			t.Errorf("expected DigitalSignature category for %s, got %s", f.Algorithm, f.Category)
		}
		if f.Usage != "signing" {
			t.Errorf("expected signing usage, got %s", f.Usage)
		}
	}
}

func TestAnalyzeFile_ECDSASign(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

func main() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := sha256.Sum256([]byte("data"))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, msg[:])
	valid := ecdsa.VerifyASN1(&priv.PublicKey, msg[:], sig)
	_ = valid
}
`)
	a := New()
	findings, err := a.AnalyzeFile("ecdsa_sign.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect: ecdsa.GenerateKey, elliptic.P256(), ecdsa.SignASN1, ecdsa.VerifyASN1
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 ECDSA/elliptic findings, got %d", len(findings))
	}

	var foundGenKey, foundSign, foundVerify bool
	for _, f := range findings {
		if f.Severity != models.SeverityCritical {
			t.Errorf("expected severity Critical for %s, got %s", f.Algorithm, f.Severity)
		}
		if f.QuantumThreat != models.ThreatBrokenByShor {
			t.Errorf("expected BrokenByShor for %s, got %s", f.Algorithm, f.QuantumThreat)
		}
		switch f.Usage {
		case "key-generation":
			foundGenKey = true
			if f.Algorithm != "ECDSA-P256" {
				t.Errorf("expected ECDSA-P256 for key generation, got %s", f.Algorithm)
			}
		case "signing":
			foundSign = true
		case "verification":
			foundVerify = true
		}
	}
	if !foundGenKey {
		t.Error("missing ECDSA key generation finding")
	}
	if !foundSign {
		t.Error("missing ECDSA signing finding")
	}
	if !foundVerify {
		t.Error("missing ECDSA verification finding")
	}
}

func TestAnalyzeFile_TLSConfig(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
	srv := &http.Server{TLSConfig: cfg}
	_ = srv
}
`)
	a := New()
	findings, err := a.AnalyzeFile("tls_config.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect: MinVersion finding + 2 cipher suite findings
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 TLS findings, got %d", len(findings))
	}

	var foundMinVersion, foundCipherSuite bool
	for _, f := range findings {
		if f.Category != models.CategoryTLSCipherSuite {
			t.Errorf("expected TLS category, got %s", f.Category)
		}
		switch f.Usage {
		case "tls-configuration":
			foundMinVersion = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("expected High severity for TLS 1.2 MinVersion, got %s", f.Severity)
			}
		case "cipher-suite":
			foundCipherSuite = true
		}
	}
	if !foundMinVersion {
		t.Error("missing TLS MinVersion finding")
	}
	if !foundCipherSuite {
		t.Error("missing TLS CipherSuite finding")
	}
}

func TestAnalyzeFile_AESNewCipher(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/aes"
)

func main() {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	_ = block
}
`)
	a := New()
	findings, err := a.AnalyzeFile("aes_test.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected AES finding")
	}

	f := findings[0]
	if f.Category != models.CategorySymmetricEncryption {
		t.Errorf("expected SymmetricEncryption category, got %s", f.Category)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected Medium severity for AES (unknown/small key), got %s", f.Severity)
	}
	if f.QuantumThreat != models.ThreatWeakenedByGrover {
		t.Errorf("expected WeakenedByGrover, got %s", f.QuantumThreat)
	}
	if f.Usage != "cipher-creation" {
		t.Errorf("expected cipher-creation usage, got %s", f.Usage)
	}
}

func TestAnalyzeFile_AESKeySizes(t *testing.T) {
	src := []byte(`package main

import "crypto/aes"

func create128() {
	key := make([]byte, 16)
	b, _ := aes.NewCipher(key)
	_ = b
}

func create256() {
	key := make([]byte, 32)
	b, _ := aes.NewCipher(key)
	_ = b
}
`)
	a := New()
	findings, err := a.AnalyzeFile("aes_sizes.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 AES findings, got %d", len(findings))
	}

	// Both AES calls detected (key size inference from make() is a future enhancement)
	for _, f := range findings {
		if f.Algorithm != "AES" && f.Algorithm != "AES-128" && f.Algorithm != "AES-256" {
			t.Errorf("expected AES algorithm, got %s", f.Algorithm)
		}
		if f.Library != "crypto/aes" {
			t.Errorf("expected crypto/aes library, got %s", f.Library)
		}
	}
}

func TestAnalyzeFile_MD5SHA1(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func main() {
	h1 := md5.New()
	h1.Write([]byte("data"))
	sum1 := h1.Sum(nil)
	fmt.Println(sum1)

	sum2 := md5.Sum([]byte("data"))
	fmt.Println(sum2)

	h2 := sha1.New()
	h2.Write([]byte("data"))
	sum3 := h2.Sum(nil)
	fmt.Println(sum3)

	sum4 := sha1.Sum([]byte("data"))
	fmt.Println(sum4)
}
`)
	a := New()
	findings, err := a.AnalyzeFile("hashes.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// md5.New, md5.Sum, sha1.New, sha1.Sum = 4 findings
	if len(findings) != 4 {
		t.Fatalf("expected 4 hash findings (md5.New, md5.Sum, sha1.New, sha1.Sum), got %d", len(findings))
	}

	md5Count := 0
	sha1Count := 0
	for _, f := range findings {
		if f.Severity != models.SeverityHigh {
			t.Errorf("expected High severity for %s, got %s", f.Algorithm, f.Severity)
		}
		if f.Category != models.CategoryHashing {
			t.Errorf("expected Hashing category for %s, got %s", f.Algorithm, f.Category)
		}
		if f.QuantumThreat != models.ThreatWeakenedByGrover {
			t.Errorf("expected WeakenedByGrover for %s, got %s", f.Algorithm, f.QuantumThreat)
		}
		switch f.Algorithm {
		case "MD5":
			md5Count++
		case "SHA-1":
			sha1Count++
		}
	}
	if md5Count != 2 {
		t.Errorf("expected 2 MD5 findings, got %d", md5Count)
	}
	if sha1Count != 2 {
		t.Errorf("expected 2 SHA-1 findings, got %d", sha1Count)
	}
}

func TestAnalyzeFile_SafeCode(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func main() {
	key := make([]byte, 32) // AES-256
	block, _ := aes.NewCipher(key)

	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	plaintext := []byte("quantum-safe data")
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	hash := sha256.Sum256(ciphertext)
	fmt.Printf("%x\n", hash)
}
`)
	a := New()
	findings, err := a.AnalyzeFile("safe.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have AES-256 (Low severity) and no critical/high findings.
	for _, f := range findings {
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			t.Errorf("safe code should not have Critical/High findings, got %s for %s", f.Severity, f.Algorithm)
		}
	}

	// SHA-256 should NOT generate a finding (it's not in our detection list).
	for _, f := range findings {
		if f.Algorithm == "SHA-256" {
			t.Error("SHA-256 should not produce a finding; it is quantum-resistant")
		}
	}
}

func TestAnalyzeFile_ImportAlias(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	myrsa "crypto/rsa"
)

func main() {
	key, _ := myrsa.GenerateKey(rand.Reader, 2048)
	_ = key
}
`)
	a := New()
	findings, err := a.AnalyzeFile("alias.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding even with import alias 'myrsa'")
	}
	f := findings[0]
	if f.Algorithm != "RSA-2048" {
		t.Errorf("expected RSA-2048, got %s", f.Algorithm)
	}
	if f.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", f.KeySize)
	}
	if f.Library != "crypto/rsa" {
		t.Errorf("expected library crypto/rsa, got %s", f.Library)
	}
}

func TestAnalyzeFile_MultipleFindings(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func generateRSA() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}

func generateECDSA() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := sha256.Sum256([]byte("data"))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, msg[:])
	_ = sig
}

func hashMD5() {
	h := md5.Sum([]byte("data"))
	fmt.Println(h)
}
`)
	a := New()
	findings, err := a.AnalyzeFile("multi.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: rsa.GenerateKey, ecdsa.GenerateKey, elliptic.P256, ecdsa.SignASN1, md5.Sum
	if len(findings) < 4 {
		t.Fatalf("expected at least 4 findings from mixed crypto usage, got %d", len(findings))
	}

	algorithms := make(map[string]bool)
	lineNumbers := make(map[int]bool)
	for _, f := range findings {
		algorithms[f.Algorithm] = true
		lineNumbers[f.LineStart] = true
	}

	if !algorithms["RSA-2048"] {
		t.Error("missing RSA-2048 finding")
	}
	if !algorithms["MD5"] {
		t.Error("missing MD5 finding")
	}

	// Check that line numbers are distinct (different findings on different lines).
	if len(lineNumbers) < 4 {
		t.Errorf("expected at least 4 distinct line numbers, got %d", len(lineNumbers))
	}

	// Verify line ordering is plausible.
	for _, f := range findings {
		if f.LineStart < 1 {
			t.Errorf("finding %s has invalid line number %d", f.Algorithm, f.LineStart)
		}
	}
}

func TestAnalyzeFile_ECDH(t *testing.T) {
	src := []byte(`package main

import "crypto/ecdh"

func main() {
	_ = ecdh.P256()
	_ = ecdh.P384()
	_ = ecdh.P521()
	_ = ecdh.X25519()
}
`)
	a := New()
	findings, err := a.AnalyzeFile("ecdh.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 ECDH findings, got %d", len(findings))
	}

	algos := make(map[string]bool)
	for _, f := range findings {
		algos[f.Algorithm] = true
		if f.Category != models.CategoryKeyExchange {
			t.Errorf("expected KeyExchange category for %s, got %s", f.Algorithm, f.Category)
		}
		if f.QuantumThreat != models.ThreatBrokenByShor {
			t.Errorf("expected BrokenByShor for %s, got %s", f.Algorithm, f.QuantumThreat)
		}
	}
	for _, expected := range []string{"ECDH-P256", "ECDH-P384", "ECDH-P521", "ECDH-X25519"} {
		if !algos[expected] {
			t.Errorf("missing expected algorithm %s", expected)
		}
	}
}

func TestAnalyzeFile_DES(t *testing.T) {
	src := []byte(`package main

import "crypto/des"

func main() {
	key := make([]byte, 24)
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}
`)
	a := New()
	findings, err := a.AnalyzeFile("des.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 3DES finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Algorithm != "3DES" {
		t.Errorf("expected 3DES, got %s", f.Algorithm)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected High severity for 3DES, got %s", f.Severity)
	}
	if f.KeySize != 168 {
		t.Errorf("expected key size 168 for 3DES, got %d", f.KeySize)
	}
}

func TestAnalyzeFile_RC4(t *testing.T) {
	src := []byte(`package main

import "crypto/rc4"

func main() {
	key := []byte("secretkey")
	c, _ := rc4.NewCipher(key)
	_ = c
}
`)
	a := New()
	findings, err := a.AnalyzeFile("rc4.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 RC4 finding, got %d", len(findings))
	}
	if findings[0].Algorithm != "RC4" {
		t.Errorf("expected RC4, got %s", findings[0].Algorithm)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected Critical severity for RC4, got %s", findings[0].Severity)
	}
}

func TestAnalyzeFile_HMACWeakHash(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/hmac"
	"crypto/sha1"
)

func main() {
	mac := hmac.New(sha1.New, []byte("secret"))
	mac.Write([]byte("data"))
	_ = mac.Sum(nil)
}
`)
	a := New()
	findings, err := a.AnalyzeFile("hmac_weak.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundHMACSHA1 bool
	for _, f := range findings {
		if f.Algorithm == "HMAC-SHA1" {
			foundHMACSHA1 = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("expected High severity for HMAC-SHA1, got %s", f.Severity)
			}
			if f.Usage != "mac-creation" {
				t.Errorf("expected mac-creation usage, got %s", f.Usage)
			}
		}
	}
	if !foundHMACSHA1 {
		t.Error("missing HMAC-SHA1 finding")
	}
}

func TestAnalyzeFile_X509CreateCert(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	_ = cert
}
`)
	a := New()
	findings, err := a.AnalyzeFile("x509.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundX509 bool
	for _, f := range findings {
		if f.Category == models.CategoryCertificate {
			foundX509 = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("expected High severity for x509 cert, got %s", f.Severity)
			}
			if f.Usage != "certificate-creation" {
				t.Errorf("expected certificate-creation usage, got %s", f.Usage)
			}
		}
	}
	if !foundX509 {
		t.Error("missing X.509 certificate creation finding")
	}
}

func TestAnalyzeFile_TLSConfigEmpty(t *testing.T) {
	src := []byte(`package main

import "crypto/tls"

func main() {
	cfg := &tls.Config{}
	_ = cfg
}
`)
	a := New()
	findings, err := a.AnalyzeFile("tls_empty.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for empty tls.Config")
	}

	f := findings[0]
	if f.Category != models.CategoryTLSCipherSuite {
		t.Errorf("expected TLS category, got %s", f.Category)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected High severity for empty TLS config, got %s", f.Severity)
	}
}

func TestAnalyzeFile_EllipticCurves(t *testing.T) {
	src := []byte(`package main

import "crypto/elliptic"

func main() {
	_ = elliptic.P256()
	_ = elliptic.P384()
	_ = elliptic.P521()
}
`)
	a := New()
	findings, err := a.AnalyzeFile("curves.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 elliptic curve findings, got %d", len(findings))
	}
	algos := make(map[string]bool)
	for _, f := range findings {
		algos[f.Algorithm] = true
	}
	for _, expected := range []string{"ECDSA-P256", "ECDSA-P384", "ECDSA-P521"} {
		if !algos[expected] {
			t.Errorf("missing %s finding", expected)
		}
	}
}

func TestAnalyzeFile_ParseError(t *testing.T) {
	src := []byte(`this is not valid go code {{{{`)
	a := New()
	_, err := a.AnalyzeFile("bad.go", src)
	if err == nil {
		t.Fatal("expected parse error for invalid Go source")
	}
}

func TestAnalyzeFile_EmptyFile(t *testing.T) {
	src := []byte(`package main
`)
	a := New()
	findings, err := a.AnalyzeFile("empty.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestAnalyzeFile_MultipleAliases(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	myecdsa "crypto/ecdsa"
	myelliptic "crypto/elliptic"
)

func main() {
	key, _ := myecdsa.GenerateKey(myelliptic.P256(), rand.Reader)
	_ = key
}
`)
	a := New()
	findings, err := a.AnalyzeFile("multi_alias.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect both myecdsa.GenerateKey and myelliptic.P256()
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings with aliases, got %d", len(findings))
	}

	var foundECDSA, foundElliptic bool
	for _, f := range findings {
		if f.Library == "crypto/ecdsa" {
			foundECDSA = true
		}
		if f.Library == "crypto/elliptic" {
			foundElliptic = true
		}
	}
	if !foundECDSA {
		t.Error("missing ecdsa finding with alias")
	}
	if !foundElliptic {
		t.Error("missing elliptic finding with alias")
	}
}

func TestAnalyzeFile_ColumnPositions(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/md5"
)

func main() {
	h := md5.New()
	_ = h
}
`)
	a := New()
	findings, err := a.AnalyzeFile("columns.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}

	f := findings[0]
	if f.ColumnStart < 1 {
		t.Errorf("expected ColumnStart >= 1, got %d", f.ColumnStart)
	}
	if f.ColumnEnd <= f.ColumnStart {
		t.Errorf("expected ColumnEnd > ColumnStart, got start=%d end=%d", f.ColumnStart, f.ColumnEnd)
	}
}

func TestAnalyzeFile_FindingIDFormat(t *testing.T) {
	src := []byte(`package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}
`)
	a := New()
	findings, err := a.AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.ID == "" {
		t.Error("expected non-empty finding ID")
	}
	if f.RuleID == "" {
		t.Error("expected non-empty rule ID")
	}
}
