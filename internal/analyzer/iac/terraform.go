// Package iac provides scanning for Infrastructure-as-Code files (Terraform
// HCL, Kubernetes YAML) to detect quantum-vulnerable cryptographic
// configurations in cloud resources and TLS settings.
package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// Analyzer scans Terraform and Kubernetes files for crypto-related configs.
type Analyzer struct{}

// New creates a new IaC analyzer.
func New() *Analyzer { return &Analyzer{} }

// tfRule defines a Terraform-specific detection pattern. It matches within a
// resource block (identified by resourceType) and looks for a field pattern.
type tfRule struct {
	resourceType *regexp.Regexp // matches "resource "type" "name" {"
	fieldPattern *regexp.Regexp // matches the vulnerable field inside the block
	algo         string
	sev          models.Severity
	threat       models.QuantumThreatLevel
	cat          models.AlgorithmCategory
	id           string
	desc         string
	repl         string
}

// k8sRule defines a Kubernetes YAML detection pattern.
type k8sRule struct {
	pattern *regexp.Regexp
	algo    string
	sev     models.Severity
	threat  models.QuantumThreatLevel
	cat     models.AlgorithmCategory
	id      string
	desc    string
	repl    string
}

// terraformRules returns rules scoped to Terraform resource blocks.
func terraformRules() []tfRule {
	return []tfRule{
		// AWS KMS key with RSA spec
		{
			resourceType: regexp.MustCompile(`resource\s+"aws_kms_key"`),
			fieldPattern: regexp.MustCompile(`customer_master_key_spec\s*=\s*"(RSA_2048|RSA_3072|RSA_4096|ECC_NIST_P256|ECC_NIST_P384|ECC_SECG_P256K1)"`),
			algo:         "KMS-RSA",
			sev:          models.SeverityCritical,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryKMS,
			id:           "QS-IAC-KMS-RSA-001",
			desc:         "AWS KMS key with quantum-vulnerable algorithm",
			repl:         "SYMMETRIC_DEFAULT (AES-256-GCM)",
		},
		// AWS KMS key with key_spec (newer TF provider)
		{
			resourceType: regexp.MustCompile(`resource\s+"aws_kms_key"`),
			fieldPattern: regexp.MustCompile(`key_spec\s*=\s*"(RSA_2048|RSA_3072|RSA_4096|ECC_NIST_P256|ECC_NIST_P384|ECC_SECG_P256K1)"`),
			algo:         "KMS-RSA",
			sev:          models.SeverityCritical,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryKMS,
			id:           "QS-IAC-KMS-SPEC-001",
			desc:         "AWS KMS key with quantum-vulnerable key spec",
			repl:         "SYMMETRIC_DEFAULT (AES-256-GCM)",
		},
		// AWS ALB/NLB listener with old TLS policy
		{
			resourceType: regexp.MustCompile(`resource\s+"aws_lb_listener"`),
			fieldPattern: regexp.MustCompile(`ssl_policy\s*=\s*"(ELBSecurityPolicy-2016-08|ELBSecurityPolicy-TLS-1-0-2015-04|ELBSecurityPolicy-TLS-1-1-2017-01|ELBSecurityPolicy-FS-2018-06)"`),
			algo:         "TLS-Legacy",
			sev:          models.SeverityHigh,
			threat:       models.ThreatWeakenedByGrover,
			cat:          models.CategoryTLSCipherSuite,
			id:           "QS-IAC-ALB-TLS-001",
			desc:         "AWS ALB/NLB listener with legacy TLS policy",
			repl:         "ELBSecurityPolicy-TLS13-1-2-2021-06",
		},
		// AWS ALB listener with any non-TLS1.3 policy
		{
			resourceType: regexp.MustCompile(`resource\s+"aws_alb_listener"`),
			fieldPattern: regexp.MustCompile(`ssl_policy\s*=\s*"(ELBSecurityPolicy-2016-08|ELBSecurityPolicy-TLS-1-0-2015-04|ELBSecurityPolicy-TLS-1-1-2017-01)"`),
			algo:         "TLS-Legacy",
			sev:          models.SeverityHigh,
			threat:       models.ThreatWeakenedByGrover,
			cat:          models.CategoryTLSCipherSuite,
			id:           "QS-IAC-ALB-TLS-002",
			desc:         "AWS ALB listener with legacy TLS policy",
			repl:         "ELBSecurityPolicy-TLS13-1-2-2021-06",
		},
		// Google Cloud SSL policy with old TLS
		{
			resourceType: regexp.MustCompile(`resource\s+"google_compute_ssl_policy"`),
			fieldPattern: regexp.MustCompile(`min_tls_version\s*=\s*"(TLS_1_0|TLS_1_1)"`),
			algo:         "TLS-1.0/1.1",
			sev:          models.SeverityHigh,
			threat:       models.ThreatWeakenedByGrover,
			cat:          models.CategoryTLSCipherSuite,
			id:           "QS-IAC-GCP-TLS-001",
			desc:         "GCP SSL policy with deprecated TLS version",
			repl:         "TLS_1_3",
		},
		// Google Cloud SSL policy with weak cipher profile
		{
			resourceType: regexp.MustCompile(`resource\s+"google_compute_ssl_policy"`),
			fieldPattern: regexp.MustCompile(`profile\s*=\s*"(COMPATIBLE|MODERN)"`),
			algo:         "TLS-WeakProfile",
			sev:          models.SeverityMedium,
			threat:       models.ThreatWeakenedByGrover,
			cat:          models.CategoryTLSCipherSuite,
			id:           "QS-IAC-GCP-PROFILE-001",
			desc:         "GCP SSL policy profile may include weak ciphers",
			repl:         "RESTRICTED profile with TLS 1.3",
		},
		// Azure Key Vault key with RSA
		{
			resourceType: regexp.MustCompile(`resource\s+"azurerm_key_vault_key"`),
			fieldPattern: regexp.MustCompile(`key_type\s*=\s*"(RSA|RSA-HSM|EC|EC-HSM)"`),
			algo:         "AKV-RSA/EC",
			sev:          models.SeverityCritical,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryKMS,
			id:           "QS-IAC-AKV-KEY-001",
			desc:         "Azure Key Vault key with quantum-vulnerable type",
			repl:         "AES-256 symmetric key or post-quantum algorithm",
		},
		// Azure Key Vault key size
		{
			resourceType: regexp.MustCompile(`resource\s+"azurerm_key_vault_key"`),
			fieldPattern: regexp.MustCompile(`key_size\s*=\s*(2048|3072|4096)`),
			algo:         "AKV-RSA",
			sev:          models.SeverityHigh,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryKMS,
			id:           "QS-IAC-AKV-SIZE-001",
			desc:         "Azure Key Vault RSA key size (quantum-vulnerable)",
			repl:         "Symmetric key (AES-256)",
		},
		// tls_private_key with RSA
		{
			resourceType: regexp.MustCompile(`resource\s+"tls_private_key"`),
			fieldPattern: regexp.MustCompile(`algorithm\s*=\s*"(RSA)"`),
			algo:         "RSA",
			sev:          models.SeverityCritical,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryCertificate,
			id:           "QS-IAC-TLS-RSA-001",
			desc:         "TLS private key using RSA algorithm",
			repl:         "Ed25519 (interim), ML-DSA-65 (post-quantum)",
		},
		// tls_private_key with ECDSA
		{
			resourceType: regexp.MustCompile(`resource\s+"tls_private_key"`),
			fieldPattern: regexp.MustCompile(`algorithm\s*=\s*"(ECDSA)"`),
			algo:         "ECDSA",
			sev:          models.SeverityCritical,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryCertificate,
			id:           "QS-IAC-TLS-ECDSA-001",
			desc:         "TLS private key using ECDSA algorithm",
			repl:         "ML-DSA-65 (post-quantum)",
		},
		// tls_private_key RSA key size
		{
			resourceType: regexp.MustCompile(`resource\s+"tls_private_key"`),
			fieldPattern: regexp.MustCompile(`rsa_bits\s*=\s*(1024|2048|3072|4096)`),
			algo:         "RSA",
			sev:          models.SeverityHigh,
			threat:       models.ThreatBrokenByShor,
			cat:          models.CategoryCertificate,
			id:           "QS-IAC-TLS-RSA-BITS-001",
			desc:         "TLS RSA key with specified bit size",
			repl:         "ML-KEM-768 / ML-DSA-65",
		},
		// AWS CloudFront with old TLS
		{
			resourceType: regexp.MustCompile(`resource\s+"aws_cloudfront_distribution"`),
			fieldPattern: regexp.MustCompile(`minimum_protocol_version\s*=\s*"(TLSv1|TLSv1_2016|TLSv1\.1_2016|SSLv3)"`),
			algo:         "TLS-Legacy",
			sev:          models.SeverityHigh,
			threat:       models.ThreatWeakenedByGrover,
			cat:          models.CategoryTLSCipherSuite,
			id:           "QS-IAC-CF-TLS-001",
			desc:         "CloudFront distribution with legacy TLS",
			repl:         "TLSv1.2_2021",
		},
	}
}

// kubernetesRules returns rules for Kubernetes YAML patterns.
func kubernetesRules() []k8sRule {
	return []k8sRule{
		// TLS secret with known weak cipher references in annotations/labels
		{
			pattern: regexp.MustCompile(`ssl-ciphers.*(?:DES|RC4|3DES|MD5|NULL|EXPORT)`),
			algo:    "TLS-WeakCipher",
			sev:     models.SeverityHigh,
			threat:  models.ThreatWeakenedByGrover,
			cat:     models.CategoryTLSCipherSuite,
			id:      "QS-IAC-K8S-CIPHER-001",
			desc:    "Kubernetes ingress with weak SSL cipher",
			repl:    "TLS 1.3 ciphers",
		},
		// Ingress with old TLS version annotation
		{
			pattern: regexp.MustCompile(`ssl-protocols.*(?:TLSv1\b|TLSv1\.0|TLSv1\.1|SSLv3)`),
			algo:    "TLS-1.0/1.1",
			sev:     models.SeverityHigh,
			threat:  models.ThreatWeakenedByGrover,
			cat:     models.CategoryTLSCipherSuite,
			id:      "QS-IAC-K8S-TLS-001",
			desc:    "Kubernetes ingress with deprecated TLS version",
			repl:    "TLSv1.3",
		},
		// nginx ingress with ssl-prefer-server-ciphers off (allows client to pick weak)
		{
			pattern: regexp.MustCompile(`min-tls-version.*["']?(1\.0|1\.1)["']?`),
			algo:    "TLS-1.0/1.1",
			sev:     models.SeverityHigh,
			threat:  models.ThreatWeakenedByGrover,
			cat:     models.CategoryTLSCipherSuite,
			id:      "QS-IAC-K8S-MINTLS-001",
			desc:    "Kubernetes config with minimum TLS 1.0/1.1",
			repl:    "TLS 1.3",
		},
		// Certificate with RSA key type
		{
			pattern: regexp.MustCompile(`keyAlgorithm:\s*(?:rsa|RSA)`),
			algo:    "RSA",
			sev:     models.SeverityCritical,
			threat:  models.ThreatBrokenByShor,
			cat:     models.CategoryCertificate,
			id:      "QS-IAC-K8S-CERT-RSA-001",
			desc:    "Kubernetes cert-manager certificate with RSA",
			repl:    "ML-DSA-65",
		},
		// Certificate with ECDSA key type
		{
			pattern: regexp.MustCompile(`keyAlgorithm:\s*(?:ecdsa|ECDSA)`),
			algo:    "ECDSA",
			sev:     models.SeverityCritical,
			threat:  models.ThreatBrokenByShor,
			cat:     models.CategoryCertificate,
			id:      "QS-IAC-K8S-CERT-ECDSA-001",
			desc:    "Kubernetes cert-manager certificate with ECDSA",
			repl:    "ML-DSA-65",
		},
		// RSA key size in cert-manager
		{
			pattern: regexp.MustCompile(`keySize:\s*(2048|3072|4096)`),
			algo:    "RSA",
			sev:     models.SeverityHigh,
			threat:  models.ThreatBrokenByShor,
			cat:     models.CategoryCertificate,
			id:      "QS-IAC-K8S-CERT-SIZE-001",
			desc:    "Kubernetes cert-manager RSA key size",
			repl:    "ML-KEM-768 / ML-DSA-65",
		},
	}
}

// AnalyzeFile scans a single file for IaC crypto patterns.
func (a *Analyzer) AnalyzeFile(filePath string, content []byte) []models.Finding {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".tf":
		return a.analyzeTerraform(filePath, content)
	case ".yaml", ".yml":
		return a.analyzeKubernetes(filePath, content)
	default:
		return nil
	}
}

// analyzeTerraform scans a .tf file using block-aware pattern matching.
func (a *Analyzer) analyzeTerraform(filePath string, content []byte) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(string(content), "\n")
	rules := terraformRules()

	// Track which resource block we're inside.
	type blockCtx struct {
		resourceType string
		startLine    int
		depth        int
	}
	var currentBlock *blockCtx

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments.
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Detect resource block start.
		resourcePat := regexp.MustCompile(`resource\s+"(\w+)"\s+"(\w+)"\s*\{`)
		if m := resourcePat.FindStringSubmatch(trimmed); len(m) >= 3 {
			currentBlock = &blockCtx{
				resourceType: m[1],
				startLine:    lineNum,
				depth:        1,
			}
			continue
		}

		// Track brace depth.
		if currentBlock != nil {
			currentBlock.depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if currentBlock.depth <= 0 {
				currentBlock = nil
				continue
			}
		}

		// Check rules against current resource block.
		for _, r := range rules {
			// Only check if we're inside a matching resource block or
			// the rule's resourceType matches a resource on this line.
			inMatchingBlock := currentBlock != nil && r.resourceType.MatchString(fmt.Sprintf(`resource "%s"`, currentBlock.resourceType))
			onResourceLine := r.resourceType.MatchString(trimmed)

			if !inMatchingBlock && !onResourceLine {
				continue
			}

			if m := r.fieldPattern.FindStringSubmatch(trimmed); len(m) >= 2 {
				algo := r.algo
				keySize := 0

				// Enrich algorithm with matched value.
				matchedVal := m[1]
				switch {
				case strings.HasPrefix(matchedVal, "RSA_"):
					algo = "RSA-" + strings.TrimPrefix(matchedVal, "RSA_")
					keySize = parseInt(strings.TrimPrefix(matchedVal, "RSA_"))
				case strings.HasPrefix(matchedVal, "ECC_"):
					algo = "EC-" + matchedVal
				case strings.HasPrefix(matchedVal, "ELB"):
					algo = matchedVal
				case matchedVal == "RSA" || matchedVal == "ECDSA":
					algo = matchedVal
				default:
					if n := parseInt(matchedVal); n > 0 {
						keySize = n
					}
				}

				f := models.Finding{
					ID:              fmt.Sprintf("iac-%s-%d-%s", filepath.Base(filePath), lineNum, r.id),
					RuleID:          r.id,
					Severity:        r.sev,
					Category:        r.cat,
					QuantumThreat:   r.threat,
					FilePath:        filePath,
					LineStart:       lineNum,
					LineEnd:         lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       algo,
					KeySize:         keySize,
					Language:        "terraform",
					Description:     r.desc,
					ReplacementAlgo: r.repl,
					Confidence:      0.90,
					CreatedAt:       time.Now(),
				}

				if currentBlock != nil {
					f.Usage = fmt.Sprintf("resource %s (line %d)", currentBlock.resourceType, currentBlock.startLine)
				}

				findings = append(findings, f)
				break
			}
		}
	}

	return findings
}

// analyzeKubernetes scans a Kubernetes YAML file for crypto patterns.
func (a *Analyzer) analyzeKubernetes(filePath string, content []byte) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(string(content), "\n")
	rules := kubernetesRules()

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, r := range rules {
			if m := r.pattern.FindStringSubmatch(line); len(m) >= 1 {
				f := models.Finding{
					ID:              fmt.Sprintf("iac-%s-%d-%s", filepath.Base(filePath), lineNum, r.id),
					RuleID:          r.id,
					Severity:        r.sev,
					Category:        r.cat,
					QuantumThreat:   r.threat,
					FilePath:        filePath,
					LineStart:       lineNum,
					LineEnd:         lineNum,
					CodeSnippet:     trimmed,
					Algorithm:       r.algo,
					Language:        "kubernetes",
					Description:     r.desc,
					ReplacementAlgo: r.repl,
					Confidence:      0.88,
					CreatedAt:       time.Now(),
				}

				// Extract key size if captured.
				if len(m) >= 2 {
					if n := parseInt(m[1]); n > 0 {
						f.KeySize = n
						if r.algo == "RSA" {
							f.Algorithm = fmt.Sprintf("RSA-%d", n)
						}
					}
				}

				findings = append(findings, f)
				break
			}
		}
	}

	return findings
}

// AnalyzeDirectory scans all IaC files in a directory.
func (a *Analyzer) AnalyzeDirectory(root string) ([]models.Finding, error) {
	var all []models.Finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			b := filepath.Base(path)
			if b == ".git" || b == ".terraform" || b == "node_modules" || b == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".tf" && ext != ".yaml" && ext != ".yml" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		findings := a.AnalyzeFile(path, content)
		all = append(all, findings...)
		return nil
	})
	return all, err
}

// parseInt parses a decimal integer from a string.
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
