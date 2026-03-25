package pyast

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

//go:embed scripts/pyast_extract.py
var extractScript []byte

type astOutput struct {
	Imports     []importInfo   `json:"imports"`
	Calls       []callInfo     `json:"calls"`
	Assignments []assignInfo   `json:"assignments"`
	Error       string         `json:"error,omitempty"`
}

type importInfo struct {
	Module string `json:"module"`
	Alias  string `json:"alias"`
	Line   int    `json:"line"`
	From   string `json:"from,omitempty"`
}

type callInfo struct {
	Func   string                 `json:"func"`
	Args   []interface{}          `json:"args"`
	Kwargs map[string]interface{} `json:"kwargs"`
	Line   int                    `json:"line"`
}

type assignInfo struct {
	Target string      `json:"target"`
	Value  interface{} `json:"value"`
	Line   int         `json:"line"`
}

// Analyzer performs Python AST analysis.
type Analyzer struct {
	pythonBin  string
	scriptPath string
}

// New creates a Python AST analyzer. Returns nil if python3 is not available.
func New() *Analyzer {
	// Check for python3
	bin, err := exec.LookPath("python3")
	if err != nil {
		return nil
	}
	// Write the embedded script to a temp file
	tmpDir := os.TempDir()
	scriptPath := filepath.Join(tmpDir, "qs_pyast_extract.py")
	os.WriteFile(scriptPath, extractScript, 0644)
	return &Analyzer{pythonBin: bin, scriptPath: scriptPath}
}

// AnalyzeFile parses a Python file and returns crypto findings.
func (a *Analyzer) AnalyzeFile(filePath string) ([]models.Finding, error) {
	if a == nil {
		return nil, fmt.Errorf("python3 not available")
	}

	// Run the extraction script
	cmd := exec.Command(a.pythonBin, a.scriptPath, filePath)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil // Gracefully skip unparseable files
	}

	var parsed astOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, nil
	}
	if parsed.Error != "" {
		return nil, nil
	}

	// Build variable resolution map
	varValues := make(map[string]string)
	for _, a := range parsed.Assignments {
		if s, ok := a.Value.(string); ok {
			varValues[a.Target] = s
		}
	}

	var findings []models.Finding

	// Analyze each call for crypto patterns
	for _, call := range parsed.Calls {
		f := a.analyzeCall(call, filePath, varValues)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (a *Analyzer) analyzeCall(call callInfo, filePath string, vars map[string]string) *models.Finding {
	fn := call.Func

	// Pattern matching for crypto calls
	type pattern struct {
		match    func(string) bool
		algo     string
		severity models.Severity
		threat   models.QuantumThreatLevel
		category models.AlgorithmCategory
		rule     string
		desc     string
		repl     string
	}

	patterns := []pattern{
		// RSA key generation
		{func(f string) bool { return f == "rsa.generate_private_key" || f == "RSA.generate" }, "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-PY-RSA-001", "RSA key generation in Python", "ML-KEM-768"},
		// ECDSA
		{func(f string) bool { return f == "ec.generate_private_key" }, "ECDSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-PY-ECDSA-001", "ECDSA key generation in Python", "ML-DSA-65"},
		// DSA
		{func(f string) bool { return f == "dsa.generate_private_key" }, "DSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryDigitalSignature, "QS-PY-DSA-001", "DSA key generation in Python", "ML-DSA-65"},
		// DH
		{func(f string) bool { return f == "dh.generate_parameters" }, "DH", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryKeyExchange, "QS-PY-DH-001", "DH key exchange in Python", "ML-KEM-768"},
		// Fernet (uses AES-128)
		{func(f string) bool { return f == "Fernet" || f == "MultiFernet" }, "AES-128 (Fernet)", models.SeverityMedium, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-PY-FERNET-001", "Fernet uses AES-128-CBC internally", "AES-256-GCM"},
		// hashlib
		{func(f string) bool { return f == "hashlib.md5" }, "MD5", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-PY-MD5-001", "MD5 hash in Python", "SHA-256"},
		{func(f string) bool { return f == "hashlib.sha1" }, "SHA-1", models.SeverityHigh, models.ThreatWeakenedByGrover, models.CategoryHashing, "QS-PY-SHA1-001", "SHA-1 hash in Python", "SHA-256"},
		// PyCryptodome
		{func(f string) bool { return f == "RSA.generate" || f == "RSA.construct" }, "RSA", models.SeverityCritical, models.ThreatBrokenByShor, models.CategoryAsymmetricEncryption, "QS-PY-RSA-002", "RSA via PyCryptodome", "ML-KEM-768"},
		{func(f string) bool { return f == "DES.new" || f == "DES3.new" }, "DES", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-PY-DES-001", "DES cipher in Python", "AES-256"},
		{func(f string) bool { return f == "ARC4.new" }, "RC4", models.SeverityCritical, models.ThreatWeakenedByGrover, models.CategorySymmetricEncryption, "QS-PY-RC4-001", "RC4 cipher in Python", "AES-256-GCM"},
		// Paramiko SSH
		{func(f string) bool { return strings.Contains(f, "paramiko") && strings.Contains(f, "RSAKey") }, "SSH-RSA", models.SeverityHigh, models.ThreatBrokenByShor, models.CategorySSH, "QS-PY-SSH-RSA-001", "Paramiko RSA SSH key", "PQ-safe SSH"},
	}

	for _, p := range patterns {
		if p.match(fn) {
			finding := &models.Finding{
				ID:              fmt.Sprintf("pyast-%s-%d-%s", filepath.Base(filePath), call.Line, p.rule),
				RuleID:          p.rule,
				Severity:        p.severity,
				Category:        p.category,
				QuantumThreat:   p.threat,
				FilePath:        filePath,
				LineStart:       call.Line,
				LineEnd:         call.Line,
				Algorithm:       p.algo,
				Usage:           fn,
				Library:         fn,
				Language:        "python",
				Description:     p.desc,
				ReplacementAlgo: p.repl,
				Confidence:      0.93,
				CreatedAt:       time.Now(),
			}

			// Extract key size from kwargs
			if ks, ok := call.Kwargs["key_size"]; ok {
				if n, ok := ks.(float64); ok {
					finding.KeySize = int(n)
					finding.Algorithm = fmt.Sprintf("%s-%d", p.algo, int(n))
				}
			}
			// Extract key size from first positional arg (PyCryptodome: RSA.generate(2048))
			if len(call.Args) > 0 {
				if n, ok := call.Args[0].(float64); ok && n >= 512 && n <= 16384 {
					finding.KeySize = int(n)
					finding.Algorithm = fmt.Sprintf("%s-%d", p.algo, int(n))
				}
			}
			// Check for curve argument (ECDSA)
			if len(call.Args) > 0 {
				if s, ok := call.Args[0].(string); ok {
					if strings.Contains(s, "SECP256R1") || strings.Contains(s, "P256") {
						finding.Algorithm = "ECDSA-P256"
					} else if strings.Contains(s, "SECP384R1") || strings.Contains(s, "P384") {
						finding.Algorithm = "ECDSA-P384"
					}
				}
			}

			return finding
		}
	}

	// Check for variable-argument patterns: MessageDigest.getInstance(algo) equivalent
	// In Python: hashlib.new(algo_var)
	if fn == "hashlib.new" && len(call.Args) > 0 {
		if varName, ok := call.Args[0].(string); ok {
			if resolved, ok := vars[varName]; ok {
				resolved = strings.ToUpper(resolved)
				if resolved == "MD5" || resolved == "SHA1" || resolved == "SHA-1" {
					return &models.Finding{
						ID:            fmt.Sprintf("pyast-%s-%d-taint", filepath.Base(filePath), call.Line),
						RuleID:        "QS-PY-TAINT-001",
						Severity:      models.SeverityHigh,
						QuantumThreat: models.ThreatWeakenedByGrover,
						Category:      models.CategoryHashing,
						FilePath:      filePath,
						LineStart:     call.Line,
						Algorithm:     resolved,
						Usage:         fmt.Sprintf("hashlib.new(%s) via variable %s", resolved, varName),
						Language:      "python",
						Description:   fmt.Sprintf("Weak hash %s via variable resolution", resolved),
						Confidence:    0.85,
						CreatedAt:     time.Now(),
					}
				}
			}
		}
	}

	return nil
}
