package depgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeTempFile writes data to a named file in a temporary directory.
func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write temp file %s: %v", name, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestParseGoMod(t *testing.T) {
	gomod := []byte(`module example.com/myapp

go 1.21

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	golang.org/x/crypto v0.17.0
	github.com/gin-gonic/gin v1.9.1
)

require (
	github.com/go-playground/validator/v10 v10.15.5 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
`)

	dir := t.TempDir()
	writeTempFile(t, dir, "go.mod", gomod)

	da := NewDepAnalyzer()
	deps, err := da.parseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("parseGoMod: %v", err)
	}

	// module line + 5 require entries = 6 entries
	if len(deps) < 6 {
		t.Fatalf("expected at least 6 deps, got %d", len(deps))
	}

	// Verify a direct dependency.
	var jwtGo *DepEntry
	for i := range deps {
		if deps[i].Name == "github.com/dgrijalva/jwt-go" {
			jwtGo = &deps[i]
			break
		}
	}
	if jwtGo == nil {
		t.Fatal("expected jwt-go dependency")
	}
	if jwtGo.Version != "v3.2.0+incompatible" {
		t.Errorf("jwt-go version: got %q, want v3.2.0+incompatible", jwtGo.Version)
	}
	if jwtGo.Language != "go" {
		t.Errorf("jwt-go language: got %q, want go", jwtGo.Language)
	}
	if !jwtGo.Direct {
		t.Error("jwt-go should be direct")
	}

	// Verify an indirect dependency.
	var sysEntry *DepEntry
	for i := range deps {
		if deps[i].Name == "golang.org/x/sys" {
			sysEntry = &deps[i]
			break
		}
	}
	if sysEntry == nil {
		t.Fatal("expected golang.org/x/sys dependency")
	}
	if sysEntry.Direct {
		t.Error("golang.org/x/sys should be indirect")
	}
}

func TestParseGoMod_SingleLineRequire(t *testing.T) {
	gomod := []byte(`module example.com/single

go 1.22

require github.com/dgrijalva/jwt-go v3.2.0+incompatible
`)

	dir := t.TempDir()
	writeTempFile(t, dir, "go.mod", gomod)

	da := NewDepAnalyzer()
	deps, err := da.parseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("parseGoMod: %v", err)
	}

	found := false
	for _, d := range deps {
		if d.Name == "github.com/dgrijalva/jwt-go" {
			found = true
			if d.Version != "v3.2.0+incompatible" {
				t.Errorf("version: got %q", d.Version)
			}
		}
	}
	if !found {
		t.Error("expected jwt-go from single-line require")
	}
}

func TestParsePackageJSON(t *testing.T) {
	pkgJSON := []byte(`{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "jsonwebtoken": "^9.0.0",
    "node-rsa": "^1.1.1"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}`)

	dir := t.TempDir()
	writeTempFile(t, dir, "package.json", pkgJSON)

	da := NewDepAnalyzer()
	deps, err := da.parsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	if len(deps) != 5 {
		t.Fatalf("expected 5 deps (3 deps + 2 devDeps), got %d", len(deps))
	}

	// Verify jsonwebtoken is present and direct.
	var jwt *DepEntry
	for i := range deps {
		if deps[i].Name == "jsonwebtoken" {
			jwt = &deps[i]
			break
		}
	}
	if jwt == nil {
		t.Fatal("expected jsonwebtoken dependency")
	}
	if jwt.Language != "javascript" {
		t.Errorf("language: got %q, want javascript", jwt.Language)
	}
	if !jwt.Direct {
		t.Error("jsonwebtoken should be direct")
	}

	// Verify devDependency is not direct.
	var jest *DepEntry
	for i := range deps {
		if deps[i].Name == "jest" {
			jest = &deps[i]
			break
		}
	}
	if jest == nil {
		t.Fatal("expected jest dev dependency")
	}
	if jest.Direct {
		t.Error("jest (devDependency) should not be direct")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	reqs := []byte(`# Crypto dependencies
cryptography==41.0.7
paramiko>=3.4.0
requests==2.31.0
pycryptodome~=3.19.0

# Comment line
flask>=3.0.0
`)

	dir := t.TempDir()
	writeTempFile(t, dir, "requirements.txt", reqs)

	da := NewDepAnalyzer()
	deps, err := da.parseRequirementsTxt(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("parseRequirementsTxt: %v", err)
	}

	if len(deps) != 5 {
		t.Fatalf("expected 5 deps, got %d", len(deps))
	}

	// Verify cryptography entry.
	var crypto *DepEntry
	for i := range deps {
		if deps[i].Name == "cryptography" {
			crypto = &deps[i]
			break
		}
	}
	if crypto == nil {
		t.Fatal("expected cryptography dependency")
	}
	if crypto.Version != "41.0.7" {
		t.Errorf("version: got %q, want 41.0.7", crypto.Version)
	}
	if crypto.Language != "python" {
		t.Errorf("language: got %q, want python", crypto.Language)
	}

	// Verify paramiko with >= operator.
	var paramiko *DepEntry
	for i := range deps {
		if deps[i].Name == "paramiko" {
			paramiko = &deps[i]
			break
		}
	}
	if paramiko == nil {
		t.Fatal("expected paramiko dependency")
	}
	if paramiko.Version != "3.4.0" {
		t.Errorf("paramiko version: got %q, want 3.4.0", paramiko.Version)
	}
}

func TestParsePomXML(t *testing.T) {
	pom := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk15on</artifactId>
      <version>1.70</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`)

	dir := t.TempDir()
	writeTempFile(t, dir, "pom.xml", pom)

	da := NewDepAnalyzer()
	deps, err := da.parsePomXML(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("parsePomXML: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	// Verify bouncycastle entry.
	var bc *DepEntry
	for i := range deps {
		if strings.Contains(deps[i].Name, "bouncycastle") {
			bc = &deps[i]
			break
		}
	}
	if bc == nil {
		t.Fatal("expected bouncycastle dependency")
	}
	if bc.Language != "java" {
		t.Errorf("language: got %q, want java", bc.Language)
	}
	if !bc.Direct {
		t.Error("bouncycastle should be direct (not test scope)")
	}

	// Verify test-scope dependency is not direct.
	var junit *DepEntry
	for i := range deps {
		if strings.Contains(deps[i].Name, "junit") {
			junit = &deps[i]
			break
		}
	}
	if junit == nil {
		t.Fatal("expected junit dependency")
	}
	if junit.Direct {
		t.Error("junit (test scope) should not be direct")
	}
}

func TestAnalyze_KnownVulnDeps(t *testing.T) {
	dir := t.TempDir()

	gomod := []byte(`module example.com/vulnapp

go 1.21

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.9.1
)
`)
	writeTempFile(t, dir, "go.mod", gomod)

	da := NewDepAnalyzer()
	graph, findings, err := da.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Should have at least one finding for jwt-go.
	if len(findings) == 0 {
		t.Fatal("expected findings for jwt-go")
	}

	var jwtFinding bool
	for _, f := range findings {
		if f.InDependency && strings.Contains(f.Library, "jwt-go") {
			jwtFinding = true
			if len(f.DependencyChain) == 0 {
				t.Error("expected non-empty DependencyChain")
			}
			if f.RuleID != "DEP-PQC-001" {
				t.Errorf("rule ID: got %q, want DEP-PQC-001", f.RuleID)
			}
			if f.ReplacementAlgo == "" {
				t.Error("expected replacement algo")
			}
		}
	}
	if !jwtFinding {
		t.Error("expected a finding with InDependency=true for jwt-go")
	}

	// Graph should contain the jwt-go node.
	if graph == nil {
		t.Fatal("graph should not be nil")
	}
	node, ok := graph.Nodes["go:github.com/dgrijalva/jwt-go"]
	if !ok {
		t.Fatal("expected jwt-go node in graph")
	}
	if len(node.CryptoFindings) == 0 {
		t.Error("expected CryptoFindings on jwt-go node")
	}
}

func TestAnalyze_MultipleManifests(t *testing.T) {
	dir := t.TempDir()

	// Go manifest with a known-vulnerable dependency.
	gomod := []byte(`module example.com/multi

go 1.21

require github.com/dgrijalva/jwt-go v3.2.0+incompatible
`)
	writeTempFile(t, dir, "go.mod", gomod)

	// Python manifest with a known-vulnerable dependency.
	reqs := []byte("cryptography==41.0.7\nflask>=3.0.0\n")
	writeTempFile(t, dir, "requirements.txt", reqs)

	da := NewDepAnalyzer()
	graph, findings, err := da.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// We expect findings from both manifests: jwt-go (Go) and cryptography (Python).
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings (jwt-go + cryptography), got %d", len(findings))
	}

	// At minimum, cryptography should produce a finding.
	foundCrypto := false
	for _, f := range findings {
		if strings.Contains(f.Library, "cryptography") {
			foundCrypto = true
		}
	}
	if !foundCrypto {
		t.Error("expected finding for Python cryptography package")
	}

	// Graph should have nodes from both ecosystems.
	if graph == nil {
		t.Fatal("graph should not be nil")
	}
	if len(graph.Nodes) < 3 {
		t.Errorf("expected at least 3 graph nodes, got %d", len(graph.Nodes))
	}
}

func TestAnalyze_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	da := NewDepAnalyzer()
	graph, findings, err := da.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings in empty dir, got %d", len(findings))
	}
	if graph == nil {
		t.Fatal("graph should not be nil even for empty dir")
	}
	if len(graph.Nodes) != 0 {
		t.Errorf("expected no graph nodes, got %d", len(graph.Nodes))
	}
}
