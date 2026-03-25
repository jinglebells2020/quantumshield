package network

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// TLSEndpointAudit represents the TLS configuration of a single endpoint.
type TLSEndpointAudit struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	TLSVersion    string `json:"tls_version"`
	CipherSuite   string `json:"cipher_suite"`
	KeyExchange   string `json:"key_exchange"`
	KeySize       int    `json:"key_size"`
	IsQuantumVuln bool   `json:"is_quantum_vulnerable"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	Replacement   string `json:"replacement"`
	CertSubject   string `json:"cert_subject,omitempty"`
	CertIssuer    string `json:"cert_issuer,omitempty"`
	CertExpiry    string `json:"cert_expiry,omitempty"`
	CertAlgorithm string `json:"cert_algorithm,omitempty"`
}

// NetworkAuditResult is the complete network TLS audit.
type NetworkAuditResult struct {
	Endpoints  []TLSEndpointAudit `json:"endpoints"`
	Total      int                `json:"total"`
	Vulnerable int                `json:"vulnerable"`
	Safe       int                `json:"safe"`
	ScanTime   time.Time          `json:"scan_time"`
}

// AuditEndpoint checks a single TLS endpoint using openssl s_client.
func AuditEndpoint(host string, port int) (*TLSEndpointAudit, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	audit := &TLSEndpointAudit{Host: host, Port: port}

	// Use openssl s_client to probe
	cmd := exec.Command("openssl", "s_client", "-connect", addr, "-brief")
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Try without -brief
		cmd = exec.Command("openssl", "s_client", "-connect", addr)
		cmd.Stdin = strings.NewReader("")
		out, _ = cmd.CombinedOutput()
	}

	output := string(out)

	// Parse TLS version
	if m := regexp.MustCompile(`Protocol\s*:\s*(\S+)`).FindStringSubmatch(output); len(m) > 1 {
		audit.TLSVersion = m[1]
	}
	if m := regexp.MustCompile(`Cipher\s*:\s*(\S+)`).FindStringSubmatch(output); len(m) > 1 {
		audit.CipherSuite = m[1]
	}

	// Parse certificate info
	if m := regexp.MustCompile(`subject=(.+)`).FindStringSubmatch(output); len(m) > 1 {
		audit.CertSubject = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`issuer=(.+)`).FindStringSubmatch(output); len(m) > 1 {
		audit.CertIssuer = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`Server public key is (\d+) bit`).FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &audit.KeySize)
	}
	if m := regexp.MustCompile(`Peer signing digest: (\S+)`).FindStringSubmatch(output); len(m) > 1 {
		audit.CertAlgorithm = m[1]
	}

	// Classify quantum vulnerability
	classifyTLS(audit)

	return audit, nil
}

// AuditEndpoints audits multiple endpoints.
func AuditEndpoints(targets []string) *NetworkAuditResult {
	result := &NetworkAuditResult{ScanTime: time.Now()}

	for _, target := range targets {
		parts := strings.SplitN(target, ":", 2)
		host := parts[0]
		port := 443
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &port)
		}

		audit, err := AuditEndpoint(host, port)
		if err != nil {
			continue
		}

		result.Endpoints = append(result.Endpoints, *audit)
		result.Total++
		if audit.IsQuantumVuln {
			result.Vulnerable++
		} else {
			result.Safe++
		}
	}

	return result
}

func classifyTLS(audit *TLSEndpointAudit) {
	suite := strings.ToUpper(audit.CipherSuite)

	// Check key exchange
	switch {
	case strings.Contains(suite, "RSA"):
		audit.KeyExchange = "RSA"
		audit.IsQuantumVuln = true
		audit.Severity = "critical"
		audit.Description = "RSA key exchange — vulnerable to Shor's algorithm"
		audit.Replacement = "TLS 1.3 with X25519+ML-KEM-768 hybrid"
	case strings.Contains(suite, "ECDHE"):
		audit.KeyExchange = "ECDHE"
		audit.IsQuantumVuln = true
		audit.Severity = "high"
		audit.Description = "ECDHE key exchange — vulnerable to Shor's algorithm"
		audit.Replacement = "TLS 1.3 with X25519+ML-KEM-768 hybrid"
	case strings.Contains(suite, "DHE"):
		audit.KeyExchange = "DHE"
		audit.IsQuantumVuln = true
		audit.Severity = "high"
		audit.Description = "DHE key exchange — vulnerable to Shor's algorithm"
		audit.Replacement = "TLS 1.3 with ML-KEM-768"
	default:
		audit.KeyExchange = "unknown"
		audit.IsQuantumVuln = false
		audit.Severity = "info"
		audit.Description = "Unknown or PQ key exchange"
	}

	// TLS version check
	if audit.TLSVersion == "TLSv1" || audit.TLSVersion == "TLSv1.1" {
		audit.Severity = "critical"
		audit.Description += " + deprecated TLS version"
	}
}
