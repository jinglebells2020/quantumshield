package models

import "time"

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func ParseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityLow
	}
}

type AlgorithmCategory int

const (
	CategoryAsymmetricEncryption AlgorithmCategory = iota
	CategoryDigitalSignature
	CategoryKeyExchange
	CategorySymmetricEncryption
	CategoryHashing
	CategoryKeyDerivation
	CategoryTLSCipherSuite
	CategoryCertificate
	CategorySSH
	CategoryKMS
)

func (c AlgorithmCategory) String() string {
	names := []string{
		"Asymmetric Encryption", "Digital Signature", "Key Exchange",
		"Symmetric Encryption", "Hashing", "Key Derivation",
		"TLS Cipher Suite", "Certificate", "SSH", "KMS",
	}
	if int(c) < len(names) {
		return names[c]
	}
	return "Unknown"
}

type QuantumThreatLevel int

const (
	ThreatBrokenByShor QuantumThreatLevel = iota
	ThreatWeakenedByGrover
	ThreatNotDirectlyThreatened
)

func (t QuantumThreatLevel) String() string {
	switch t {
	case ThreatBrokenByShor:
		return "Shor"
	case ThreatWeakenedByGrover:
		return "Grover"
	case ThreatNotDirectlyThreatened:
		return "Safe"
	default:
		return "Unknown"
	}
}

type Finding struct {
	ID              string             `json:"id"`
	ScanID          string             `json:"scan_id"`
	RuleID          string             `json:"rule_id"`
	Severity        Severity           `json:"severity"`
	Category        AlgorithmCategory  `json:"category"`
	QuantumThreat   QuantumThreatLevel `json:"quantum_threat"`
	FilePath        string             `json:"file_path"`
	LineStart       int                `json:"line_start"`
	LineEnd         int                `json:"line_end"`
	ColumnStart     int                `json:"column_start"`
	ColumnEnd       int                `json:"column_end"`
	CodeSnippet     string             `json:"code_snippet"`
	Algorithm       string             `json:"algorithm"`
	KeySize         int                `json:"key_size,omitempty"`
	Usage           string             `json:"usage"`
	Library         string             `json:"library"`
	Language        string             `json:"language"`
	Description     string             `json:"description"`
	DataSensitivity string             `json:"data_sensitivity,omitempty"`
	InDependency    bool               `json:"in_dependency"`
	DependencyChain []string           `json:"dependency_chain,omitempty"`
	RecommendedFix  string             `json:"recommended_fix,omitempty"`
	ReplacementAlgo string             `json:"replacement_algo,omitempty"`
	MigrationEffort string             `json:"migration_effort"`
	AutoFixAvailable bool             `json:"auto_fix_available"`
	FixDiff         string             `json:"fix_diff,omitempty"`
	ComplianceRefs  []ComplianceRef    `json:"compliance_refs,omitempty"`
	Confidence      float64            `json:"confidence"`
	FalsePositive   bool               `json:"false_positive"`
	CreatedAt       time.Time          `json:"created_at"`
}

type ComplianceRef struct {
	Framework   string `json:"framework"`
	Requirement string `json:"requirement"`
	Status      string `json:"status"`
}
