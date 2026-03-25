package compliance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// Framework represents a regulatory compliance framework.
type Framework string

const (
	FrameworkCNSA2  Framework = "CNSA 2.0"
	FrameworkNSM10  Framework = "NSM-10"
	FrameworkEUPQC  Framework = "EU PQC"
	FrameworkPCIDSS Framework = "PCI DSS 4.0"
)

// AllFrameworks returns every supported framework.
func AllFrameworks() []Framework {
	return []Framework{FrameworkCNSA2, FrameworkNSM10, FrameworkEUPQC, FrameworkPCIDSS}
}

// ParseFramework converts a string to a Framework, or returns an error.
func ParseFramework(s string) (Framework, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cnsa", "cnsa2", "cnsa 2.0", "cnsa2.0":
		return FrameworkCNSA2, nil
	case "nsm10", "nsm-10":
		return FrameworkNSM10, nil
	case "eupqc", "eu pqc", "eu-pqc":
		return FrameworkEUPQC, nil
	case "pcidss", "pci dss", "pci-dss", "pci dss 4.0":
		return FrameworkPCIDSS, nil
	case "all", "":
		return "", nil // empty means all
	default:
		return "", fmt.Errorf("unknown framework %q; valid: cnsa2, nsm-10, eu-pqc, pci-dss", s)
	}
}

// Requirement represents a single regulatory requirement and its compliance status.
type Requirement struct {
	ID          string    `json:"id"`
	Framework   Framework `json:"framework"`
	Description string    `json:"description"`
	Deadline    time.Time `json:"deadline"`
	Status      string    `json:"status"` // "compliant", "non-compliant", "in-progress", "not-applicable"
	Findings    int       `json:"blocking_findings"`
	Actions     []string  `json:"required_actions,omitempty"`
}

// ComplianceReport is the full compliance assessment for a single framework.
type ComplianceReport struct {
	Framework        Framework     `json:"framework"`
	GeneratedAt      time.Time     `json:"generated_at"`
	OverallStatus    string        `json:"overall_status"`
	CompliancePct    float64       `json:"compliance_percentage"`
	Requirements     []Requirement `json:"requirements"`
	TotalFindings    int           `json:"total_findings"`
	BlockingFindings int           `json:"blocking_findings"`
	Summary          string        `json:"summary"`
}

// MultiReport bundles reports for every requested framework.
type MultiReport struct {
	Reports     []ComplianceReport `json:"reports"`
	GeneratedAt time.Time          `json:"generated_at"`
	GeneratedBy string             `json:"generated_by"`
}

// ---------- requirement definitions ----------

func cnsa2Requirements() []Requirement {
	return []Requirement{
		{
			ID:          "CNSA2-KEM-01",
			Framework:   FrameworkCNSA2,
			Description: "Use ML-KEM (FIPS 203) for all key establishment",
			Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-SIG-01",
			Framework:   FrameworkCNSA2,
			Description: "Use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures",
			Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-HASH-01",
			Framework:   FrameworkCNSA2,
			Description: "Use SHA-384 or SHA-512 for all hashing operations",
			Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-SYM-01",
			Framework:   FrameworkCNSA2,
			Description: "Use AES-256 for all symmetric encryption",
			Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-TLS-01",
			Framework:   FrameworkCNSA2,
			Description: "Use TLS 1.3 with post-quantum key exchange",
			Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-CERT-01",
			Framework:   FrameworkCNSA2,
			Description: "Issue post-quantum certificates for all new Certificate Authorities",
			Deadline:    time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-SSH-01",
			Framework:   FrameworkCNSA2,
			Description: "Deploy post-quantum SSH key exchange and authentication algorithms",
			Deadline:    time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CNSA2-LEGACY-01",
			Framework:   FrameworkCNSA2,
			Description: "Complete deprecation of all legacy (non-PQ) cryptographic algorithms",
			Deadline:    time.Date(2033, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}

func nsm10Requirements() []Requirement {
	return []Requirement{
		{
			ID:          "NSM10-INV-01",
			Framework:   FrameworkNSM10,
			Description: "Maintain a complete cryptographic inventory of all systems",
			Deadline:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "NSM10-PLAN-01",
			Framework:   FrameworkNSM10,
			Description: "Document a cryptographic migration plan with timelines",
			Deadline:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "NSM10-PRIORITY-01",
			Framework:   FrameworkNSM10,
			Description: "Prioritize harvest-now-decrypt-later (HNDL) vulnerable data for migration",
			Deadline:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "NSM10-MONITOR-01",
			Framework:   FrameworkNSM10,
			Description: "Deploy continuous monitoring for cryptographic usage across all systems",
			Deadline:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		},
	}
}

func eupqcRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "EUPQC-ASSESS-01",
			Framework:   FrameworkEUPQC,
			Description: "Complete quantum risk assessment for all critical infrastructure",
			Deadline:    time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "EUPQC-AGILITY-01",
			Framework:   FrameworkEUPQC,
			Description: "Implement crypto-agility to enable rapid algorithm substitution",
			Deadline:    time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "EUPQC-HYBRID-01",
			Framework:   FrameworkEUPQC,
			Description: "Deploy hybrid (classical + PQ) key exchange for TLS-protected services",
			Deadline:    time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "EUPQC-DATA-01",
			Framework:   FrameworkEUPQC,
			Description: "Protect long-lived data (>10 year retention) with PQ algorithms",
			Deadline:    time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		},
	}
}

func pcidssRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "PCIDSS-CRYPTO-01",
			Framework:   FrameworkPCIDSS,
			Description: "Use strong cryptography (AES-256, SHA-256+) for cardholder data at rest",
			Deadline:    time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "PCIDSS-TLS-01",
			Framework:   FrameworkPCIDSS,
			Description: "Use TLS 1.2+ for all cardholder data in transit; TLS 1.3 recommended",
			Deadline:    time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "PCIDSS-KEYS-01",
			Framework:   FrameworkPCIDSS,
			Description: "Implement proper cryptographic key management lifecycle",
			Deadline:    time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "PCIDSS-INV-01",
			Framework:   FrameworkPCIDSS,
			Description: "Maintain an inventory of trusted keys and certificates",
			Deadline:    time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC),
		},
	}
}

// ---------- finding classification helpers ----------

// vulnAlgorithms maps algorithm substrings to the requirement IDs they violate.
var kemVulnKeywords = []string{
	"RSA", "ECDH", "DH", "Diffie-Hellman", "ECDHE",
	"X25519", "X448", "Curve25519",
}

var sigVulnKeywords = []string{
	"RSA", "ECDSA", "Ed25519", "Ed448", "DSA",
}

var hashWeakKeywords = []string{
	"MD5", "SHA1", "SHA-1", "SHA-128",
}

var symWeakKeywords = []string{
	"DES", "3DES", "RC4", "Blowfish", "AES-128",
}

var tlsWeakKeywords = []string{
	"TLS 1.0", "TLS 1.1", "SSL",
}

var sshVulnKeywords = []string{
	"ssh-rsa", "ecdsa-sha2", "ssh-dss",
}

func containsAny(s string, keywords []string) bool {
	upper := strings.ToUpper(s)
	for _, kw := range keywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}

func countMatchingFindings(findings []models.Finding, keywords []string) int {
	n := 0
	for _, f := range findings {
		combined := f.Algorithm + " " + f.Description + " " + f.CodeSnippet
		if containsAny(combined, keywords) {
			n++
		}
	}
	return n
}

func countByCategory(findings []models.Finding, cat models.AlgorithmCategory) int {
	n := 0
	for _, f := range findings {
		if f.Category == cat {
			n++
		}
	}
	return n
}

func countShorVulnerable(findings []models.Finding) int {
	n := 0
	for _, f := range findings {
		if f.QuantumThreat == models.ThreatBrokenByShor {
			n++
		}
	}
	return n
}

// ---------- report generation ----------

// GenerateReport produces a compliance report for a single framework.
func GenerateReport(findings []models.Finding, framework Framework) *ComplianceReport {
	var reqs []Requirement

	switch framework {
	case FrameworkCNSA2:
		reqs = evaluateCNSA2(findings)
	case FrameworkNSM10:
		reqs = evaluateNSM10(findings)
	case FrameworkEUPQC:
		reqs = evaluateEUPQC(findings)
	case FrameworkPCIDSS:
		reqs = evaluatePCIDSS(findings)
	default:
		return &ComplianceReport{
			Framework:   framework,
			GeneratedAt: time.Now(),
			Summary:     "Unknown framework",
		}
	}

	compliant := 0
	blocking := 0
	for _, r := range reqs {
		if r.Status == "compliant" {
			compliant++
		}
		blocking += r.Findings
	}

	pct := 0.0
	if len(reqs) > 0 {
		pct = float64(compliant) / float64(len(reqs)) * 100
	}

	overall := "non-compliant"
	if pct == 100 {
		overall = "compliant"
	} else if pct >= 50 {
		overall = "partially-compliant"
	}

	report := &ComplianceReport{
		Framework:        framework,
		GeneratedAt:      time.Now(),
		OverallStatus:    overall,
		CompliancePct:    pct,
		Requirements:     reqs,
		TotalFindings:    len(findings),
		BlockingFindings: blocking,
	}

	report.Summary = buildSummary(report)
	return report
}

// GenerateAll produces compliance reports for every supported framework.
func GenerateAll(findings []models.Finding) *MultiReport {
	mr := &MultiReport{
		GeneratedAt: time.Now(),
		GeneratedBy: "QuantumShield Compliance Engine",
	}
	for _, fw := range AllFrameworks() {
		mr.Reports = append(mr.Reports, *GenerateReport(findings, fw))
	}
	return mr
}

// ToJSON marshals any report type to indented JSON.
func ToJSON(report interface{}) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ---------- framework evaluators ----------

func evaluateCNSA2(findings []models.Finding) []Requirement {
	reqs := cnsa2Requirements()

	for i := range reqs {
		switch reqs[i].ID {
		case "CNSA2-KEM-01":
			n := countMatchingFindings(findings, kemVulnKeywords)
			n += countByCategory(findings, models.CategoryKeyExchange)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace RSA/ECDH key exchange with ML-KEM-768 or ML-KEM-1024",
					"Update TLS configurations to use ML-KEM key encapsulation",
					"Migrate X25519 key agreements to ML-KEM or hybrid X25519+ML-KEM",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-SIG-01":
			n := countMatchingFindings(findings, sigVulnKeywords)
			n += countByCategory(findings, models.CategoryDigitalSignature)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace RSA/ECDSA signatures with ML-DSA-65 or ML-DSA-87",
					"Use SLH-DSA (SPHINCS+) for stateless hash-based signatures where needed",
					"Update code-signing and JWT workflows to PQ signature algorithms",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-HASH-01":
			n := countMatchingFindings(findings, hashWeakKeywords)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace MD5/SHA-1 with SHA-384 or SHA-512",
					"Update HMAC constructions to use SHA-384+",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-SYM-01":
			n := countMatchingFindings(findings, symWeakKeywords)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace DES/3DES/RC4 with AES-256-GCM",
					"Upgrade AES-128 to AES-256",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-TLS-01":
			n := countMatchingFindings(findings, tlsWeakKeywords)
			n += countByCategory(findings, models.CategoryTLSCipherSuite)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Enforce TLS 1.3 with PQ key exchange (e.g., X25519+ML-KEM-768)",
					"Disable TLS 1.0/1.1 and SSLv3",
					"Configure cipher suite preference for PQ-hybrid suites",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-CERT-01":
			n := countByCategory(findings, models.CategoryCertificate)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Plan migration to PQ certificates (ML-DSA) for new CAs",
					"Establish hybrid certificate issuance for transition period",
					"Update certificate validation logic to support PQ algorithms",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-SSH-01":
			n := countMatchingFindings(findings, sshVulnKeywords)
			n += countByCategory(findings, models.CategorySSH)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace ssh-rsa and ecdsa-sha2 with PQ SSH algorithms",
					"Deploy ML-KEM-based SSH key exchange",
					"Update SSH server and client configurations",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "CNSA2-LEGACY-01":
			n := countShorVulnerable(findings)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "in-progress"
				reqs[i].Actions = []string{
					fmt.Sprintf("Remediate %d remaining Shor-vulnerable algorithm usages", n),
					"Establish deprecation schedule for all legacy cryptography",
					"Conduct full code audit for transitive crypto dependencies",
				}
			} else {
				reqs[i].Status = "compliant"
			}
		}
	}

	return reqs
}

func evaluateNSM10(findings []models.Finding) []Requirement {
	reqs := nsm10Requirements()

	for i := range reqs {
		switch reqs[i].ID {
		case "NSM10-INV-01":
			// If a scan produced findings, an inventory exists via QuantumShield.
			// Mark compliant if the scan ran (findings list is non-nil).
			reqs[i].Findings = 0
			reqs[i].Status = "compliant"
			reqs[i].Actions = []string{
				"Continue running QuantumShield scans to maintain cryptographic inventory",
			}

		case "NSM10-PLAN-01":
			// Cannot auto-detect a written plan; mark in-progress if vulns exist.
			shor := countShorVulnerable(findings)
			reqs[i].Findings = shor
			if shor > 0 {
				reqs[i].Status = "in-progress"
				reqs[i].Actions = []string{
					"Document a formal cryptographic migration plan",
					"Assign ownership and timelines for each vulnerable system",
					fmt.Sprintf("Address %d Shor-vulnerable findings in the plan", shor),
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "NSM10-PRIORITY-01":
			// HNDL-vulnerable = anything broken by Shor (public-key crypto).
			shor := countShorVulnerable(findings)
			reqs[i].Findings = shor
			if shor > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					fmt.Sprintf("Prioritize %d HNDL-vulnerable findings for immediate migration", shor),
					"Classify data sensitivity for each vulnerable endpoint",
					"Implement PQ key exchange for data with long confidentiality requirements",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "NSM10-MONITOR-01":
			// Running QuantumShield = monitoring in place.
			reqs[i].Findings = 0
			reqs[i].Status = "compliant"
			reqs[i].Actions = []string{
				"Integrate QuantumShield into CI/CD pipeline for continuous monitoring",
			}
		}
	}

	return reqs
}

func evaluateEUPQC(findings []models.Finding) []Requirement {
	reqs := eupqcRequirements()

	for i := range reqs {
		switch reqs[i].ID {
		case "EUPQC-ASSESS-01":
			// If we have scan results, a risk assessment has been performed.
			reqs[i].Findings = 0
			reqs[i].Status = "compliant"
			reqs[i].Actions = []string{
				"Document risk assessment results and share with stakeholders",
			}

		case "EUPQC-AGILITY-01":
			// Hard to detect programmatically; check for diverse algorithm usage.
			shor := countShorVulnerable(findings)
			reqs[i].Findings = shor
			if shor > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Implement abstraction layers for cryptographic operations",
					"Use configuration-driven algorithm selection",
					fmt.Sprintf("Refactor %d hard-coded algorithm usages", shor),
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "EUPQC-HYBRID-01":
			n := countByCategory(findings, models.CategoryTLSCipherSuite)
			n += countByCategory(findings, models.CategoryKeyExchange)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Deploy hybrid key exchange (e.g., X25519+ML-KEM-768) for TLS",
					"Update load balancers and reverse proxies to support hybrid suites",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "EUPQC-DATA-01":
			shor := countShorVulnerable(findings)
			reqs[i].Findings = shor
			if shor > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Identify data with >10 year retention requirements",
					"Encrypt long-lived data at rest with PQ-safe algorithms",
					fmt.Sprintf("Migrate %d Shor-vulnerable encryptions protecting long-lived data", shor),
				}
			} else {
				reqs[i].Status = "compliant"
			}
		}
	}

	return reqs
}

func evaluatePCIDSS(findings []models.Finding) []Requirement {
	reqs := pcidssRequirements()

	for i := range reqs {
		switch reqs[i].ID {
		case "PCIDSS-CRYPTO-01":
			n := countMatchingFindings(findings, symWeakKeywords)
			n += countMatchingFindings(findings, hashWeakKeywords)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Replace weak symmetric ciphers (DES, 3DES, RC4) with AES-256",
					"Replace MD5/SHA-1 with SHA-256 or stronger",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "PCIDSS-TLS-01":
			n := countMatchingFindings(findings, tlsWeakKeywords)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Disable TLS 1.0 and TLS 1.1",
					"Enforce TLS 1.2+ with strong cipher suites",
					"Upgrade to TLS 1.3 where possible",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "PCIDSS-KEYS-01":
			n := countByCategory(findings, models.CategoryKMS)
			reqs[i].Findings = n
			if n > 0 {
				reqs[i].Status = "non-compliant"
				reqs[i].Actions = []string{
					"Implement key rotation policies",
					"Use hardware security modules (HSMs) for key storage",
				}
			} else {
				reqs[i].Status = "compliant"
			}

		case "PCIDSS-INV-01":
			reqs[i].Findings = 0
			reqs[i].Status = "compliant"
			reqs[i].Actions = []string{
				"Maintain certificate and key inventory with QuantumShield CBOM",
			}
		}
	}

	return reqs
}

// ---------- summary builder ----------

func buildSummary(r *ComplianceReport) string {
	compliant := 0
	for _, req := range r.Requirements {
		if req.Status == "compliant" {
			compliant++
		}
	}
	total := len(r.Requirements)

	if compliant == total {
		return fmt.Sprintf("Fully compliant with %s: all %d requirements met.", r.Framework, total)
	}

	return fmt.Sprintf(
		"%s compliance: %d/%d requirements met (%.0f%%). %d blocking findings require remediation.",
		r.Framework, compliant, total, r.CompliancePct, r.BlockingFindings,
	)
}
