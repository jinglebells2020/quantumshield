package githistory

import (
	"strings"
	"testing"
)

func TestGeneratePreCommitHook(t *testing.T) {
	hook := GeneratePreCommitHook()

	if !strings.Contains(hook, "qs scan") {
		t.Error("pre-commit hook must contain 'qs scan' command")
	}

	if !strings.Contains(hook, "--ci") {
		t.Error("pre-commit hook must use --ci flag")
	}

	if !strings.Contains(hook, "--ci-threshold 0") {
		t.Error("pre-commit hook must use --ci-threshold 0")
	}

	if !strings.HasPrefix(hook, "#!/usr/bin/env bash") {
		t.Error("pre-commit hook must start with bash shebang")
	}

	if !strings.Contains(hook, "--no-verify") {
		t.Error("pre-commit hook should mention --no-verify bypass option")
	}

	if !strings.Contains(hook, "git diff --cached") {
		t.Error("pre-commit hook must scan staged files via git diff --cached")
	}
}

func TestGenerateGitHubAction(t *testing.T) {
	action := GenerateGitHubAction()

	if !strings.Contains(action, "qs scan") {
		t.Error("GitHub Action must contain 'qs scan' command")
	}

	if !strings.Contains(action, "sarif") {
		t.Error("GitHub Action must reference sarif format")
	}

	if !strings.Contains(action, "pull_request") {
		t.Error("GitHub Action must trigger on pull_request")
	}

	if !strings.Contains(action, "upload-sarif") {
		t.Error("GitHub Action must upload SARIF results")
	}

	if !strings.Contains(action, "actions/checkout") {
		t.Error("GitHub Action must checkout code")
	}

	if !strings.Contains(action, "security-events: write") {
		t.Error("GitHub Action must request security-events write permission for SARIF upload")
	}
}

func TestScanDiffForCrypto(t *testing.T) {
	tests := []struct {
		name         string
		diff         string
		wantAdded    bool
		wantRemoved  bool
		wantPQC      bool
	}{
		{
			name: "added RSA key generation",
			diff: `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,3 +1,5 @@
 package main
+import "crypto/rsa"
+key, _ := rsa.GenerateKey(rand.Reader, 2048)
`,
			wantAdded:   true,
			wantRemoved: false,
			wantPQC:     false,
		},
		{
			name: "removed MD5 usage",
			diff: `diff --git a/hash.go b/hash.go
--- a/hash.go
+++ b/hash.go
@@ -1,3 +1,3 @@
 package main
-h := md5.New()
+h := sha256.New()
`,
			wantAdded:   false,
			wantRemoved: true,
			wantPQC:     false,
		},
		{
			name: "added PQC library",
			diff: `diff --git a/crypto.go b/crypto.go
--- a/crypto.go
+++ b/crypto.go
@@ -1,3 +1,5 @@
 package main
+import "crypto/mlkem"
+key, _ := mlkem.GenerateKey768()
`,
			wantAdded:   false,
			wantRemoved: false,
			wantPQC:     true,
		},
		{
			name: "no crypto changes",
			diff: `diff --git a/readme.md b/readme.md
--- a/readme.md
+++ b/readme.md
@@ -1,3 +1,3 @@
-# Old Title
+# New Title
`,
			wantAdded:   false,
			wantRemoved: false,
			wantPQC:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed, pqc := scanDiffForCrypto(tt.diff)
			if added != tt.wantAdded {
				t.Errorf("addedVulns = %v, want %v", added, tt.wantAdded)
			}
			if removed != tt.wantRemoved {
				t.Errorf("removedVulns = %v, want %v", removed, tt.wantRemoved)
			}
			if pqc != tt.wantPQC {
				t.Errorf("addedPQC = %v, want %v", pqc, tt.wantPQC)
			}
		})
	}
}

func TestClassifyCommit(t *testing.T) {
	tests := []struct {
		name         string
		addedVulns   bool
		removedVulns bool
		addedPQC     bool
		want         string
	}{
		{"introduces vulnerability", true, false, false, "introduces_vuln"},
		{"fixes vulnerability", false, true, false, "fixes_vuln"},
		{"introduces PQC", false, false, true, "introduces_safe"},
		{"PQC takes priority over vulns", true, true, true, "introduces_safe"},
		{"no crypto changes", false, false, false, "no_crypto_change"},
		{"replaces vuln with vuln", true, true, false, "introduces_vuln"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCommit(tt.addedVulns, tt.removedVulns, tt.addedPQC)
			if got != tt.want {
				t.Errorf("classifyCommit(%v, %v, %v) = %q, want %q",
					tt.addedVulns, tt.removedVulns, tt.addedPQC, got, tt.want)
			}
		})
	}
}

func TestFilterCryptoFiles(t *testing.T) {
	files := []string{
		"main.go",
		"README.md",
		"crypto.py",
		"image.png",
		"config.conf",
		"cert.pem",
		"styles.css",
		"handler.java",
		"app.js",
		"key.crt",
	}

	result := filterCryptoFiles(files)

	expected := map[string]bool{
		"main.go":     true,
		"crypto.py":   true,
		"config.conf": true,
		"cert.pem":    true,
		"handler.java": true,
		"app.js":      true,
		"key.crt":     true,
	}

	if len(result) != len(expected) {
		t.Errorf("filterCryptoFiles returned %d files, want %d", len(result), len(expected))
	}

	for _, f := range result {
		if !expected[f] {
			t.Errorf("unexpected file in result: %s", f)
		}
	}
}

func TestMatchesCryptoPattern(t *testing.T) {
	positives := []string{
		"key, _ := rsa.GenerateKey(rand.Reader, 2048)",
		"import crypto/md5",
		"h := sha1.New()",
		"cipher, _ := des.NewCipher(key)",
		"stream := rc4.NewCipher(key)",
		"ecdsa.GenerateKey(elliptic.P256(), rand.Reader)",
		"tls.Config{MinVersion: tls.VersionTLS12}",
		"hashlib.md5(data)",
		"MessageDigest.getInstance(\"SHA-1\")",
		"KeyPairGenerator.getInstance(\"RSA\")",
	}

	for _, line := range positives {
		if !matchesCryptoPattern(line) {
			t.Errorf("matchesCryptoPattern(%q) = false, want true", line)
		}
	}

	negatives := []string{
		"fmt.Println(\"hello world\")",
		"x := 42",
		"import os",
	}

	for _, line := range negatives {
		if matchesCryptoPattern(line) {
			t.Errorf("matchesCryptoPattern(%q) = true, want false", line)
		}
	}
}

func TestMatchesPQCPattern(t *testing.T) {
	positives := []string{
		"key, _ := mlkem.GenerateKey768()",
		"import crypto/mlkem",
		"using ML-KEM for key encapsulation",
		"mldsa.GenerateKey65()",
		"ML-DSA-65 post-quantum signature",
		"dilithium key generation",
		"kyber768 key exchange",
		"PQC migration complete",
		"post-quantum cryptography",
	}

	for _, line := range positives {
		if !matchesPQCPattern(line) {
			t.Errorf("matchesPQCPattern(%q) = false, want true", line)
		}
	}

	negatives := []string{
		"rsa.GenerateKey(rand.Reader, 2048)",
		"md5.New()",
		"fmt.Println(\"hello\")",
	}

	for _, line := range negatives {
		if matchesPQCPattern(line) {
			t.Errorf("matchesPQCPattern(%q) = true, want false", line)
		}
	}
}
