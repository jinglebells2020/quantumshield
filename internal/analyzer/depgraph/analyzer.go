package depgraph

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// DepEntry represents a single dependency extracted from a manifest file.
type DepEntry struct {
	Name     string
	Version  string
	Language string
	Direct   bool
}

// vulnPackage describes why a dependency is quantum-vulnerable.
type vulnPackage struct {
	Algorithms  string // e.g. "RSA/ECDSA"
	Replacement string // recommended PQC replacement
}

// knownVulnerablePackages maps dependency names to vulnerability metadata.
// These packages rely on classical asymmetric or weak symmetric cryptography.
var knownVulnerablePackages = map[string]vulnPackage{
	// Go standard library
	"crypto/rsa":   {Algorithms: "RSA", Replacement: "ML-KEM / ML-DSA"},
	"crypto/ecdsa": {Algorithms: "ECDSA", Replacement: "ML-DSA"},
	"crypto/ecdh":  {Algorithms: "ECDH", Replacement: "ML-KEM"},
	"crypto/des":   {Algorithms: "DES/3DES", Replacement: "AES-256"},
	"crypto/rc4":   {Algorithms: "RC4", Replacement: "AES-256-GCM"},

	// Go third-party
	"github.com/dgrijalva/jwt-go": {Algorithms: "RSA/ECDSA", Replacement: "PQC-aware JWT library"},
	"golang.org/x/crypto/ssh":     {Algorithms: "RSA/ECDSA", Replacement: "PQC-aware SSH"},

	// Python
	"pycryptodome": {Algorithms: "RSA/ECDSA/DES", Replacement: "liboqs-python"},
	"cryptography": {Algorithms: "RSA/ECDSA/DH", Replacement: "liboqs-python"},
	"paramiko":     {Algorithms: "RSA/ECDSA", Replacement: "PQC-aware SSH library"},
	"pyopenssl":    {Algorithms: "RSA/ECDSA", Replacement: "liboqs-python"},
	"pyOpenSSL":    {Algorithms: "RSA/ECDSA", Replacement: "liboqs-python"},

	// JavaScript / Node.js
	"node-forge":    {Algorithms: "RSA/ECDSA", Replacement: "liboqs-node"},
	"node-rsa":      {Algorithms: "RSA", Replacement: "ML-KEM / ML-DSA"},
	"crypto-js":     {Algorithms: "DES/AES-CBC", Replacement: "AES-256-GCM with PQC KEM"},
	"jsonwebtoken":  {Algorithms: "RSA/ECDSA", Replacement: "PQC-aware JWT library"},

	// Java
	"org.bouncycastle": {Algorithms: "RSA/ECDSA", Replacement: "BC-PQC provider"},
}

// DepAnalyzer parses dependency manifest files and checks for
// quantum-vulnerable packages.
type DepAnalyzer struct{}

// NewDepAnalyzer returns a ready-to-use analyzer.
func NewDepAnalyzer() *DepAnalyzer {
	return &DepAnalyzer{}
}

// Analyze walks root looking for known manifest files (go.mod, package.json,
// requirements.txt, pom.xml), parses each, builds a dependency graph, and
// flags quantum-vulnerable dependencies.
func (da *DepAnalyzer) Analyze(root string) (*models.DependencyGraph, []models.Finding, error) {
	graph := &models.DependencyGraph{
		Nodes: make(map[string]*models.DependencyNode),
	}
	var findings []models.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		name := filepath.Base(path)
		var deps []DepEntry
		var parseErr error

		switch name {
		case "go.mod":
			deps, parseErr = da.parseGoMod(path)
		case "package.json":
			deps, parseErr = da.parsePackageJSON(path)
		case "requirements.txt":
			deps, parseErr = da.parseRequirementsTxt(path)
		case "pom.xml":
			deps, parseErr = da.parsePomXML(path)
		default:
			return nil
		}

		if parseErr != nil {
			return nil // skip unparseable manifests
		}

		for _, dep := range deps {
			nodeKey := dep.Language + ":" + dep.Name
			if _, exists := graph.Nodes[nodeKey]; !exists {
				graph.Nodes[nodeKey] = &models.DependencyNode{
					Name:     dep.Name,
					Version:  dep.Version,
					Language: dep.Language,
				}
			}

			// Check if this dependency is in the vulnerable database.
			if f, ok := checkVulnerable(dep, path); ok {
				findings = append(findings, f)
				graph.Nodes[nodeKey].CryptoFindings = append(graph.Nodes[nodeKey].CryptoFindings, f)
			}
		}

		return nil
	})

	if err != nil {
		return graph, findings, fmt.Errorf("depgraph: walk %s: %w", root, err)
	}

	return graph, findings, nil
}

// parseGoMod extracts dependencies from a go.mod file.
func (da *DepAnalyzer) parseGoMod(path string) ([]DepEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	var entries []DepEntry
	lines := strings.Split(string(data), "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect start/end of require block.
		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Single-line require: require github.com/foo/bar v1.2.3
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				entries = append(entries, DepEntry{
					Name:     parts[1],
					Version:  parts[2],
					Language: "go",
					Direct:   !strings.Contains(line, "// indirect"),
				})
			}
			continue
		}

		// Inside a require block: github.com/foo/bar v1.2.3 // indirect
		if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				entries = append(entries, DepEntry{
					Name:     parts[0],
					Version:  parts[1],
					Language: "go",
					Direct:   !strings.Contains(line, "// indirect"),
				})
			}
		}

		// module directive → set as root package name.
		if strings.HasPrefix(line, "module ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				entries = append(entries, DepEntry{
					Name:     parts[1],
					Version:  "",
					Language: "go",
					Direct:   true,
				})
			}
		}
	}

	return entries, nil
}

// packageJSON is a minimal representation of a Node.js package.json.
type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parsePackageJSON extracts dependencies from a package.json file.
func (da *DepAnalyzer) parsePackageJSON(path string) ([]DepEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	var entries []DepEntry

	for name, version := range pkg.Dependencies {
		entries = append(entries, DepEntry{
			Name:     name,
			Version:  version,
			Language: "javascript",
			Direct:   true,
		})
	}

	for name, version := range pkg.DevDependencies {
		entries = append(entries, DepEntry{
			Name:     name,
			Version:  version,
			Language: "javascript",
			Direct:   false,
		})
	}

	return entries, nil
}

// parseRequirementsTxt extracts dependencies from a Python requirements.txt.
func (da *DepAnalyzer) parseRequirementsTxt(path string) ([]DepEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read requirements.txt: %w", err)
	}
	defer f.Close()

	var entries []DepEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip blanks, comments, and option lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		name, version := parseRequirementLine(line)
		if name == "" {
			continue
		}

		entries = append(entries, DepEntry{
			Name:     name,
			Version:  version,
			Language: "python",
			Direct:   true,
		})
	}

	return entries, scanner.Err()
}

// parseRequirementLine splits a requirements.txt line such as
// "package==1.2.3" or "package>=1.0" into name and version.
func parseRequirementLine(line string) (string, string) {
	// Try the common operators in order of specificity.
	for _, op := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(line, op); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+len(op):])
			// Strip extras like [security]
			if bracket := strings.Index(name, "["); bracket > 0 {
				name = name[:bracket]
			}
			return name, version
		}
	}
	// No version specifier — just a package name.
	name := strings.TrimSpace(line)
	if bracket := strings.Index(name, "["); bracket > 0 {
		name = name[:bracket]
	}
	return name, ""
}

// pomXML represents a minimal Maven pom.xml structure.
type pomXML struct {
	XMLName      xml.Name      `xml:"project"`
	GroupID      string        `xml:"groupId"`
	ArtifactID   string        `xml:"artifactId"`
	Version      string        `xml:"version"`
	Dependencies pomDepWrapper `xml:"dependencies"`
}

type pomDepWrapper struct {
	Entries []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// parsePomXML extracts dependencies from a Maven pom.xml.
func (da *DepAnalyzer) parsePomXML(path string) ([]DepEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pom.xml: %w", err)
	}

	var p pomXML
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	var entries []DepEntry
	for _, d := range p.Dependencies.Entries {
		name := d.GroupID
		if d.ArtifactID != "" {
			name = d.GroupID + ":" + d.ArtifactID
		}
		entries = append(entries, DepEntry{
			Name:     name,
			Version:  d.Version,
			Language: "java",
			Direct:   d.Scope != "test",
		})
	}

	return entries, nil
}

// checkVulnerable checks if a dependency entry matches a known
// quantum-vulnerable package. It returns a Finding if so.
func checkVulnerable(dep DepEntry, manifestPath string) (models.Finding, bool) {
	// Look up by exact name first, then check if the dep name contains a
	// known prefix (handles cases like "org.bouncycastle:bcprov-jdk15on").
	vuln, found := knownVulnerablePackages[dep.Name]
	if !found {
		vuln, found = matchVulnPrefix(dep.Name)
	}
	if !found {
		return models.Finding{}, false
	}

	return models.Finding{
		RuleID:        "DEP-PQC-001",
		Severity:      models.SeverityHigh,
		Category:      models.CategoryAsymmetricEncryption,
		QuantumThreat: models.ThreatBrokenByShor,
		FilePath:      manifestPath,
		Algorithm:     vuln.Algorithms,
		Description: fmt.Sprintf(
			"Dependency %q (version %s) uses quantum-vulnerable algorithms (%s). Consider migrating to %s.",
			dep.Name, dep.Version, vuln.Algorithms, vuln.Replacement,
		),
		Library:         dep.Name,
		Language:        dep.Language,
		InDependency:    true,
		DependencyChain: []string{dep.Name},
		ReplacementAlgo: vuln.Replacement,
		RecommendedFix:  fmt.Sprintf("Replace %s with %s", dep.Name, vuln.Replacement),
		MigrationEffort: "medium",
		Confidence:      0.9,
		CreatedAt:       time.Now(),
	}, true
}

// matchVulnPrefix checks if depName starts with any known vulnerable package
// name. This handles cases like Java group IDs (org.bouncycastle:bcprov-...).
func matchVulnPrefix(depName string) (vulnPackage, bool) {
	for prefix, vuln := range knownVulnerablePackages {
		if strings.HasPrefix(depName, prefix) {
			return vuln, true
		}
	}
	return vulnPackage{}, false
}
