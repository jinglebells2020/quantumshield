package cloud

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// KMSKeyAudit represents an audited cloud KMS key.
type KMSKeyAudit struct {
	Provider      string    `json:"provider"`
	KeyID         string    `json:"key_id"`
	KeyType       string    `json:"key_type"`
	KeyUsage      string    `json:"key_usage"`
	KeyState      string    `json:"key_state"`
	Region        string    `json:"region,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	IsQuantumVuln bool      `json:"is_quantum_vulnerable"`
	Severity      string    `json:"severity"`
	Replacement   string    `json:"replacement"`
	Description   string    `json:"description"`
}

// AuditResult contains the complete KMS audit.
type AuditResult struct {
	Provider    string        `json:"provider"`
	KeysAudited int          `json:"keys_audited"`
	Vulnerable  int          `json:"vulnerable"`
	Safe        int          `json:"safe"`
	Keys        []KMSKeyAudit `json:"keys"`
	Error       string        `json:"error,omitempty"`
}

// AuditAWSKMS audits AWS KMS keys using the aws CLI.
func AuditAWSKMS(region string) (*AuditResult, error) {
	result := &AuditResult{Provider: "aws"}

	// List keys
	args := []string{"kms", "list-keys", "--output", "json"}
	if region != "" {
		args = append(args, "--region", region)
	}
	out, err := exec.Command("aws", args...).Output()
	if err != nil {
		result.Error = fmt.Sprintf("aws kms list-keys failed: %v", err)
		return result, nil
	}

	var listResp struct {
		Keys []struct {
			KeyId string `json:"KeyId"`
		} `json:"Keys"`
	}
	if err := json.Unmarshal(out, &listResp); err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result, nil
	}

	for _, k := range listResp.Keys {
		// Describe each key
		descArgs := []string{"kms", "describe-key", "--key-id", k.KeyId, "--output", "json"}
		if region != "" {
			descArgs = append(descArgs, "--region", region)
		}
		descOut, err := exec.Command("aws", descArgs...).Output()
		if err != nil {
			continue
		}

		var descResp struct {
			KeyMetadata struct {
				KeyId                 string  `json:"KeyId"`
				KeyState              string  `json:"KeyState"`
				KeyUsage              string  `json:"KeyUsage"`
				CustomerMasterKeySpec string  `json:"CustomerMasterKeySpec"`
				KeySpec               string  `json:"KeySpec"`
				CreationDate          float64 `json:"CreationDate"`
			} `json:"KeyMetadata"`
		}
		if err := json.Unmarshal(descOut, &descResp); err != nil {
			continue
		}

		km := descResp.KeyMetadata
		spec := km.KeySpec
		if spec == "" {
			spec = km.CustomerMasterKeySpec
		}

		audit := KMSKeyAudit{
			Provider: "aws",
			KeyID:    km.KeyId,
			KeyType:  spec,
			KeyUsage: km.KeyUsage,
			KeyState: km.KeyState,
			Region:   region,
		}
		if km.CreationDate > 0 {
			audit.CreatedAt = time.Unix(int64(km.CreationDate), 0)
		}

		classifyKey(&audit, spec)
		result.Keys = append(result.Keys, audit)
		result.KeysAudited++
		if audit.IsQuantumVuln {
			result.Vulnerable++
		} else {
			result.Safe++
		}
	}

	return result, nil
}

// AuditGCPKMS audits Google Cloud KMS keys.
func AuditGCPKMS(project string) (*AuditResult, error) {
	result := &AuditResult{Provider: "gcp"}

	// List keyrings
	out, err := exec.Command("gcloud", "kms", "keyrings", "list",
		"--project", project, "--location", "global", "--format", "json").Output()
	if err != nil {
		result.Error = fmt.Sprintf("gcloud kms list failed: %v", err)
		return result, nil
	}

	var keyrings []struct {
		Name string `json:"name"`
	}
	json.Unmarshal(out, &keyrings)

	for _, kr := range keyrings {
		keysOut, err := exec.Command("gcloud", "kms", "keys", "list",
			"--keyring", kr.Name, "--format", "json").Output()
		if err != nil {
			continue
		}

		var keys []struct {
			Name            string `json:"name"`
			Purpose         string `json:"purpose"`
			VersionTemplate struct {
				Algorithm string `json:"algorithm"`
			} `json:"versionTemplate"`
		}
		json.Unmarshal(keysOut, &keys)

		for _, k := range keys {
			audit := KMSKeyAudit{
				Provider: "gcp",
				KeyID:    k.Name,
				KeyType:  k.VersionTemplate.Algorithm,
				KeyUsage: k.Purpose,
				KeyState: "ENABLED",
			}
			classifyKey(&audit, k.VersionTemplate.Algorithm)
			result.Keys = append(result.Keys, audit)
			result.KeysAudited++
			if audit.IsQuantumVuln {
				result.Vulnerable++
			} else {
				result.Safe++
			}
		}
	}

	return result, nil
}

// AuditAzureKV audits Azure Key Vault keys.
func AuditAzureKV(vaultName string) (*AuditResult, error) {
	result := &AuditResult{Provider: "azure"}

	out, err := exec.Command("az", "keyvault", "key", "list",
		"--vault-name", vaultName, "--output", "json").Output()
	if err != nil {
		result.Error = fmt.Sprintf("az keyvault failed: %v", err)
		return result, nil
	}

	var keys []struct {
		Kid        string `json:"kid"`
		Attributes struct {
			Enabled bool   `json:"enabled"`
			Created string `json:"created"`
		} `json:"attributes"`
	}
	json.Unmarshal(out, &keys)

	for _, k := range keys {
		// Get key details
		detailOut, err := exec.Command("az", "keyvault", "key", "show",
			"--id", k.Kid, "--output", "json").Output()
		if err != nil {
			continue
		}

		var detail struct {
			Key struct {
				Kty    string   `json:"kty"`
				KeyOps []string `json:"key_ops"`
				N      string   `json:"n"`   // RSA modulus (base64)
				Crv    string   `json:"crv"` // EC curve
			} `json:"key"`
		}
		json.Unmarshal(detailOut, &detail)

		keyType := detail.Key.Kty
		if detail.Key.Crv != "" {
			keyType += "-" + detail.Key.Crv
		}

		audit := KMSKeyAudit{
			Provider: "azure",
			KeyID:    k.Kid,
			KeyType:  keyType,
			KeyUsage: strings.Join(detail.Key.KeyOps, ","),
			KeyState: "Enabled",
		}
		classifyKey(&audit, keyType)
		result.Keys = append(result.Keys, audit)
		result.KeysAudited++
		if audit.IsQuantumVuln {
			result.Vulnerable++
		} else {
			result.Safe++
		}
	}

	return result, nil
}

func classifyKey(audit *KMSKeyAudit, spec string) {
	upper := strings.ToUpper(spec)
	switch {
	case strings.Contains(upper, "RSA"):
		audit.IsQuantumVuln = true
		audit.Severity = "critical"
		audit.Replacement = "SYMMETRIC_DEFAULT (AES-256) or await PQC KMS support"
		audit.Description = "RSA key vulnerable to Shor's algorithm"
	case strings.Contains(upper, "ECC") || strings.Contains(upper, "EC_") || strings.Contains(upper, "ECDSA") || strings.Contains(upper, "SECP"):
		audit.IsQuantumVuln = true
		audit.Severity = "critical"
		audit.Replacement = "SYMMETRIC_DEFAULT (AES-256) or await PQC KMS support"
		audit.Description = "Elliptic curve key vulnerable to Shor's algorithm"
	case strings.Contains(upper, "HMAC_SHA_256") || strings.Contains(upper, "HMAC_SHA_384") || strings.Contains(upper, "HMAC_SHA_512"):
		audit.IsQuantumVuln = false
		audit.Severity = "safe"
		audit.Description = "HMAC with strong hash — quantum safe"
	case strings.Contains(upper, "SYMMETRIC") || strings.Contains(upper, "AES"):
		audit.IsQuantumVuln = false
		audit.Severity = "safe"
		audit.Description = "AES-256 symmetric key — quantum safe (Grover halves security to 128-bit, still adequate)"
	default:
		audit.IsQuantumVuln = false
		audit.Severity = "unknown"
		audit.Description = "Unknown key type — manual review required"
	}
}
