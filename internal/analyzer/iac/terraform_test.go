package iac

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestAnalyzeFile_TerraformKMS(t *testing.T) {
	src := []byte(`resource "aws_kms_key" "main" {
  description             = "Main encryption key"
  customer_master_key_spec = "RSA_2048"
  deletion_window_in_days = 7
}
`)

	a := New()
	findings := a.AnalyzeFile("main.tf", src)

	if len(findings) == 0 {
		t.Fatal("expected findings for aws_kms_key with RSA_2048, got none")
	}

	f := findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Category != models.CategoryKMS {
		t.Errorf("expected KMS category, got %s", f.Category)
	}
	t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
}

func TestAnalyzeFile_TerraformALB(t *testing.T) {
	src := []byte(`resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.main.arn
}
`)

	a := New()
	findings := a.AnalyzeFile("alb.tf", src)

	if len(findings) == 0 {
		t.Fatal("expected findings for old ssl_policy, got none")
	}

	f := findings[0]
	if f.Category != models.CategoryTLSCipherSuite {
		t.Errorf("expected TLS Cipher Suite category, got %s", f.Category)
	}
	t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
}

func TestAnalyzeFile_TerraformTLSKey(t *testing.T) {
	src := []byte(`resource "tls_private_key" "cert" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
`)

	a := New()
	findings := a.AnalyzeFile("tls.tf", src)

	if len(findings) < 1 {
		t.Fatal("expected findings for tls_private_key RSA, got none")
	}

	foundRSA := false
	for _, f := range findings {
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
		if f.Algorithm == "RSA" && f.Severity == models.SeverityCritical {
			foundRSA = true
		}
	}
	if !foundRSA {
		t.Error("expected CRITICAL RSA finding for tls_private_key")
	}
}

func TestAnalyzeFile_GCPSSLPolicy(t *testing.T) {
	src := []byte(`resource "google_compute_ssl_policy" "legacy" {
  name            = "legacy-ssl-policy"
  min_tls_version = "TLS_1_0"
  profile         = "COMPATIBLE"
}
`)

	a := New()
	findings := a.AnalyzeFile("gcp.tf", src)

	if len(findings) < 1 {
		t.Fatal("expected findings for GCP SSL policy, got none")
	}

	for _, f := range findings {
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_AzureKeyVault(t *testing.T) {
	src := []byte(`resource "azurerm_key_vault_key" "generated" {
  name         = "generated-key"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
}
`)

	a := New()
	findings := a.AnalyzeFile("azure.tf", src)

	if len(findings) == 0 {
		t.Fatal("expected findings for Azure Key Vault RSA key, got none")
	}

	for _, f := range findings {
		if f.Severity != models.SeverityCritical && f.Severity != models.SeverityHigh {
			t.Errorf("expected CRITICAL or HIGH severity for Azure KV, got %s", f.Severity)
		}
		t.Logf("[%s] %s (keySize=%d) at line %d: %s", f.Severity, f.Algorithm, f.KeySize, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_KubernetesCertManager(t *testing.T) {
	src := []byte(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
spec:
  secretName: my-cert-tls
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
  keyAlgorithm: RSA
  keySize: 2048
  dnsNames:
    - example.com
`)

	a := New()
	findings := a.AnalyzeFile("cert.yaml", src)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings for cert-manager YAML, got %d", len(findings))
	}

	for _, f := range findings {
		t.Logf("[%s] %s (keySize=%d) at line %d: %s (lang=%s)", f.Severity, f.Algorithm, f.KeySize, f.LineStart, f.Description, f.Language)
	}
}

func TestAnalyzeFile_KubernetesIngress(t *testing.T) {
	src := []byte(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
    nginx.ingress.kubernetes.io/ssl-ciphers: "DES-CBC3-SHA:RC4-SHA"
`)

	a := New()
	findings := a.AnalyzeFile("ingress.yaml", src)

	if len(findings) < 1 {
		t.Fatal("expected findings for K8s ingress with weak ciphers, got none")
	}

	for _, f := range findings {
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_SkipsComments(t *testing.T) {
	tfSrc := []byte(`# resource "aws_kms_key" "test" {
#   customer_master_key_spec = "RSA_2048"
# }
`)

	a := New()
	findings := a.AnalyzeFile("commented.tf", tfSrc)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for commented TF code, got %d", len(findings))
	}
}

func TestAnalyzeFile_UnsupportedExtension(t *testing.T) {
	a := New()
	findings := a.AnalyzeFile("readme.md", []byte(`RSA is bad`))

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .md file, got %d", len(findings))
	}
}
