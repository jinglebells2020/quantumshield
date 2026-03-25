package cbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// CycloneDX v1.6 CBOM structures

type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component *MetaComp `json:"component,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type MetaComp struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
}

type Component struct {
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	OID                 string               `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive              string   `json:"primitive"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment"`
	ImplementationPlatform string   `json:"implementationPlatform"`
	CryptoFunctions        []string `json:"cryptoFunctions"`
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel"`
	QuantumSecurityLevel   int      `json:"quantumSecurityLevel"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

type Occurrence struct {
	Location string `json:"location"`
}

type Vulnerability struct {
	ID             string         `json:"id"`
	Description    string         `json:"description"`
	Ratings        []Rating       `json:"ratings"`
	Recommendation string         `json:"recommendation"`
	Affects        []AffectedComp `json:"affects,omitempty"`
}

type Rating struct {
	Severity string       `json:"severity"`
	Method   string       `json:"method"`
	Source   RatingSource `json:"source"`
}

type RatingSource struct {
	Name string `json:"name"`
}

type AffectedComp struct {
	Ref string `json:"ref"`
}

// Generator produces CBOMs from scan results.
type Generator struct {
	projectName    string
	projectVersion string
}

// NewGenerator creates a CBOM generator.
func NewGenerator(projectName, projectVersion string) *Generator {
	return &Generator{projectName: projectName, projectVersion: projectVersion}
}

// Generate creates a CycloneDX v1.6 CBOM from scan findings.
func (g *Generator) Generate(findings []models.Finding) *BOM {
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:qs-%d", time.Now().UnixNano()),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []Tool{{Name: "QuantumShield", Version: "1.0.0"}},
			Component: &MetaComp{Name: g.projectName, Version: g.projectVersion, Type: "application"},
		},
	}

	// Group findings by algorithm to build components
	algoGroups := make(map[string][]models.Finding)
	for _, f := range findings {
		algoGroups[f.Algorithm] = append(algoGroups[f.Algorithm], f)
	}

	for algo, group := range algoGroups {
		component := Component{
			Type: "cryptographic-asset",
			Name: algo,
			CryptoProperties: &CryptoProperties{
				AssetType:           "algorithm",
				AlgorithmProperties: buildAlgoProperties(algo, group),
				OID:                 getOID(algo),
			},
			Evidence: &Evidence{},
		}

		for _, f := range group {
			component.Evidence.Occurrences = append(component.Evidence.Occurrences, Occurrence{
				Location: fmt.Sprintf("%s:%d", f.FilePath, f.LineStart),
			})
		}

		bom.Components = append(bom.Components, component)

		// Add vulnerability entry
		if len(group) > 0 && group[0].QuantumThreat == models.ThreatBrokenByShor {
			sev := "critical"
			if group[0].Severity == models.SeverityHigh {
				sev = "high"
			}
			if group[0].Severity == models.SeverityMedium {
				sev = "medium"
			}

			rec := group[0].ReplacementAlgo
			if rec == "" {
				rec = "Migrate to post-quantum algorithm"
			}

			bom.Vulnerabilities = append(bom.Vulnerabilities, Vulnerability{
				ID:             group[0].RuleID,
				Description:    fmt.Sprintf("%s is vulnerable to quantum attack", algo),
				Ratings:        []Rating{{Severity: sev, Method: "other", Source: RatingSource{Name: "QuantumShield"}}},
				Recommendation: fmt.Sprintf("Migrate to %s", rec),
			})
		}
	}

	return bom
}

// ToJSON returns the CBOM as formatted JSON.
func (g *Generator) ToJSON(bom *BOM) ([]byte, error) {
	return json.MarshalIndent(bom, "", "  ")
}

// ToCSV returns the CBOM as CSV for compliance teams.
func (g *Generator) ToCSV(bom *BOM) string {
	var sb strings.Builder
	sb.WriteString("Algorithm,Type,Primitive,KeySize,ClassicalBits,QuantumBits,OID,Occurrences,QuantumVulnerable\n")
	for _, c := range bom.Components {
		if c.CryptoProperties == nil {
			continue
		}
		ap := c.CryptoProperties.AlgorithmProperties
		if ap == nil {
			continue
		}
		qVuln := ap.QuantumSecurityLevel == 0
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%d,%d,%s,%d,%t\n",
			c.Name, c.CryptoProperties.AssetType, ap.Primitive,
			ap.ParameterSetIdentifier, ap.ClassicalSecurityLevel,
			ap.QuantumSecurityLevel, c.CryptoProperties.OID,
			len(c.Evidence.Occurrences), qVuln))
	}
	return sb.String()
}

func buildAlgoProperties(algo string, findings []models.Finding) *AlgorithmProperties {
	ap := &AlgorithmProperties{
		ExecutionEnvironment:   "software",
		ImplementationPlatform: findings[0].Language,
	}

	// Determine primitive and security levels
	switch {
	case strings.Contains(algo, "RSA"):
		ap.Primitive = "pke"
		ap.ClassicalSecurityLevel = 112
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"keygen", "encrypt", "sign"}
		// Extract key size
		for _, f := range findings {
			if f.KeySize > 0 {
				ap.ParameterSetIdentifier = fmt.Sprintf("%d", f.KeySize)
				if f.KeySize >= 3072 {
					ap.ClassicalSecurityLevel = 128
				}
				if f.KeySize >= 4096 {
					ap.ClassicalSecurityLevel = 140
				}
				break
			}
		}
	case strings.Contains(algo, "ECDSA"):
		ap.Primitive = "sig"
		ap.ClassicalSecurityLevel = 128
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"keygen", "sign", "verify"}
		if strings.Contains(algo, "P256") {
			ap.ParameterSetIdentifier = "P-256"
		}
		if strings.Contains(algo, "P384") {
			ap.ParameterSetIdentifier = "P-384"
			ap.ClassicalSecurityLevel = 192
		}
	case strings.Contains(algo, "ECDH"):
		ap.Primitive = "kem"
		ap.ClassicalSecurityLevel = 128
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"keygen", "keyagree"}
		if strings.Contains(algo, "X25519") {
			ap.ParameterSetIdentifier = "X25519"
		}
	case strings.Contains(algo, "AES"):
		ap.Primitive = "ae"
		ap.CryptoFunctions = []string{"encrypt", "decrypt"}
		if strings.Contains(algo, "128") {
			ap.ParameterSetIdentifier = "128"
			ap.ClassicalSecurityLevel = 128
			ap.QuantumSecurityLevel = 64
		} else {
			ap.ParameterSetIdentifier = "256"
			ap.ClassicalSecurityLevel = 256
			ap.QuantumSecurityLevel = 128
		}
	case algo == "DES" || algo == "3DES":
		ap.Primitive = "ae"
		ap.ClassicalSecurityLevel = 56
		if algo == "3DES" {
			ap.ClassicalSecurityLevel = 112
		}
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"encrypt", "decrypt"}
	case algo == "MD5" || algo == "SHA-1":
		ap.Primitive = "hash"
		ap.ClassicalSecurityLevel = 0
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"digest"}
	case strings.Contains(algo, "TLS"):
		ap.Primitive = "kex"
		ap.ClassicalSecurityLevel = 128
		ap.QuantumSecurityLevel = 0
		ap.CryptoFunctions = []string{"keyexchange"}
	default:
		ap.Primitive = "other"
		ap.ClassicalSecurityLevel = 0
		ap.QuantumSecurityLevel = 0
	}

	return ap
}

func getOID(algo string) string {
	// Ordered from most specific to least specific to ensure correct matching.
	type oidEntry struct {
		prefix string
		oid    string
	}
	oids := []oidEntry{
		{"AES-128", "2.16.840.1.101.3.4.1.6"},
		{"AES-256", "2.16.840.1.101.3.4.1.46"},
		{"AES", "2.16.840.1.101.3.4.1"},
		{"3DES", "1.2.840.113549.3.7"},
		{"ECDSA", "1.2.840.10045.2.1"},
		{"ECDH", "1.3.132.1.12"},
		{"RSA", "1.2.840.113549.1.1.1"},
		{"DES", "1.3.14.3.2.7"},
		{"SHA-1", "1.3.14.3.2.26"},
		{"MD5", "1.2.840.113549.2.5"},
	}
	for _, e := range oids {
		if strings.Contains(algo, e.prefix) {
			return e.oid
		}
	}
	return ""
}
