package rules

import "quantumshield/pkg/models"

type Pattern struct {
	Language  string   `yaml:"language"`
	Type      string   `yaml:"type"`
	Patterns  []string `yaml:"patterns"`
	Packages  []string `yaml:"packages,omitempty"`
	Functions []string `yaml:"functions,omitempty"`
	Message   string   `yaml:"message"`
}

type Rule struct {
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	Description    string                 `yaml:"description"`
	Severity       string                 `yaml:"severity"`
	QuantumThreat  string                 `yaml:"quantum_threat"`
	Category       string                 `yaml:"category"`
	Replacement    string                 `yaml:"replacement"`
	ComplianceRefs []models.ComplianceRef `yaml:"compliance,omitempty"`
	Patterns       []Pattern              `yaml:"patterns"`
}

func (r *Rule) SeverityLevel() models.Severity {
	return models.ParseSeverity(r.Severity)
}

func (r *Rule) ThreatLevel() models.QuantumThreatLevel {
	switch r.QuantumThreat {
	case "broken_by_shor":
		return models.ThreatBrokenByShor
	case "weakened_by_grover":
		return models.ThreatWeakenedByGrover
	default:
		return models.ThreatNotDirectlyThreatened
	}
}

func (r *Rule) CategoryType() models.AlgorithmCategory {
	switch r.Category {
	case "asymmetric_encryption":
		return models.CategoryAsymmetricEncryption
	case "digital_signature":
		return models.CategoryDigitalSignature
	case "key_exchange":
		return models.CategoryKeyExchange
	case "symmetric_encryption":
		return models.CategorySymmetricEncryption
	case "hashing":
		return models.CategoryHashing
	case "tls_cipher_suite":
		return models.CategoryTLSCipherSuite
	case "certificate":
		return models.CategoryCertificate
	case "ssh":
		return models.CategorySSH
	default:
		return models.CategoryAsymmetricEncryption
	}
}
