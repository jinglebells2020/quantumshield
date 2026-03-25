package certwatch

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertInfo contains parsed certificate information with risk assessment.
type CertInfo struct {
	FilePath       string    `json:"file_path"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SerialNumber   string    `json:"serial_number"`
	DNSNames       []string  `json:"dns_names,omitempty"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	DaysToExpiry   int       `json:"days_to_expiry"`
	IsExpired      bool      `json:"is_expired"`
	PublicKeyAlgo  string    `json:"public_key_algorithm"`
	PublicKeySize  int       `json:"public_key_size"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	IsQuantumVuln  bool      `json:"is_quantum_vulnerable"`
	QuantumRisk    string    `json:"quantum_risk"`  // "critical", "high", "medium", "low", "safe"
	RiskReason     string    `json:"risk_reason"`
	Replacement    string    `json:"replacement"`
	IsCA           bool      `json:"is_ca"`
	ChainLength    int       `json:"chain_length"`
}

// CertWatcher monitors certificates for quantum risk and expiry.
type CertWatcher struct {
	certs []CertInfo
}

// New creates a CertWatcher.
func New() *CertWatcher {
	return &CertWatcher{}
}

// ScanDirectory finds and analyzes all certificates in a directory.
func (cw *CertWatcher) ScanDirectory(root string) ([]CertInfo, error) {
	cw.certs = nil
	certExts := map[string]bool{".pem": true, ".crt": true, ".cer": true, ".der": true, ".cert": true}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if info.IsDir() {
			b := filepath.Base(path)
			if b == ".git" || b == "vendor" || b == "node_modules" { return filepath.SkipDir }
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !certExts[ext] { return nil }
		if info.Size() > 1<<20 { return nil } // Skip >1MB

		data, err := os.ReadFile(path)
		if err != nil { return nil }

		certs := cw.parseCerts(data, path)
		cw.certs = append(cw.certs, certs...)
		return nil
	})
	return cw.certs, err
}

func (cw *CertWatcher) parseCerts(data []byte, filePath string) []CertInfo {
	var results []CertInfo
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil { break }
		if block.Type != "CERTIFICATE" { continue }

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil { continue }

		info := cw.analyzeCert(cert, filePath)
		results = append(results, info)
	}

	// Try DER if no PEM blocks found
	if len(results) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			results = append(results, cw.analyzeCert(cert, filePath))
		}
	}

	return results
}

func (cw *CertWatcher) analyzeCert(cert *x509.Certificate, filePath string) CertInfo {
	now := time.Now()
	daysToExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := CertInfo{
		FilePath:      filePath,
		Subject:       cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		SerialNumber:  cert.SerialNumber.String(),
		DNSNames:      cert.DNSNames,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysToExpiry:  daysToExpiry,
		IsExpired:     now.After(cert.NotAfter),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		IsCA:          cert.IsCA,
	}

	// Extract public key info
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyAlgo = "RSA"
		info.PublicKeySize = pub.N.BitLen()
		info.IsQuantumVuln = true
		info.Replacement = "ML-KEM / ML-DSA certificates"
	case *ecdsa.PublicKey:
		info.PublicKeyAlgo = "ECDSA"
		info.PublicKeySize = pub.Params().BitSize
		info.IsQuantumVuln = true
		info.Replacement = "ML-DSA / SLH-DSA certificates"
	default:
		info.PublicKeyAlgo = fmt.Sprintf("%T", cert.PublicKey)
		if strings.Contains(info.PublicKeyAlgo, "ed25519") {
			info.IsQuantumVuln = true
			info.Replacement = "ML-DSA certificates"
		}
	}

	// Quantum risk assessment
	if !info.IsQuantumVuln {
		info.QuantumRisk = "safe"
		info.RiskReason = "Algorithm is not quantum-vulnerable"
	} else if daysToExpiry < 0 {
		info.QuantumRisk = "low"
		info.RiskReason = "Certificate already expired"
	} else if cert.NotAfter.Year() <= 2027 {
		info.QuantumRisk = "medium"
		info.RiskReason = fmt.Sprintf("Expires %s — before likely CRQC threat window", cert.NotAfter.Format("2006-01-02"))
	} else if cert.NotAfter.Year() <= 2030 {
		info.QuantumRisk = "high"
		info.RiskReason = fmt.Sprintf("Expires %s — within CNSA 2.0 transition period", cert.NotAfter.Format("2006-01-02"))
	} else {
		info.QuantumRisk = "critical"
		info.RiskReason = fmt.Sprintf("Expires %s — will be in use when quantum computers may break %s", cert.NotAfter.Format("2006-01-02"), info.PublicKeyAlgo)
	}

	if info.IsCA {
		info.QuantumRisk = "critical"
		info.RiskReason = "CA certificate with quantum-vulnerable key — all issued certificates at risk"
	}

	return info
}

// GetExpiring returns certificates expiring within N days.
func (cw *CertWatcher) GetExpiring(days int) []CertInfo {
	var result []CertInfo
	for _, c := range cw.certs {
		if c.DaysToExpiry >= 0 && c.DaysToExpiry <= days {
			result = append(result, c)
		}
	}
	return result
}

// GetQuantumVulnerable returns only quantum-vulnerable certificates.
func (cw *CertWatcher) GetQuantumVulnerable() []CertInfo {
	var result []CertInfo
	for _, c := range cw.certs {
		if c.IsQuantumVuln {
			result = append(result, c)
		}
	}
	return result
}

// GetCriticalRisk returns certificates with critical quantum risk.
func (cw *CertWatcher) GetCriticalRisk() []CertInfo {
	var result []CertInfo
	for _, c := range cw.certs {
		if c.QuantumRisk == "critical" {
			result = append(result, c)
		}
	}
	return result
}
