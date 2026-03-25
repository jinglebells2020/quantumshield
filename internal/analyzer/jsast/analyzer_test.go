package jsast

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestAnalyzeFile_NodeCrypto(t *testing.T) {
	src := []byte(`const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
});

const hash = crypto.createHash('md5').update('test').digest('hex');
const sha1 = crypto.createHash('sha1').update('test').digest('hex');
const encrypted = crypto.publicEncrypt(publicKey, Buffer.from('secret'));
`)

	a := New()
	findings := a.AnalyzeFile("crypto_rsa.js", src)

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	algos := make(map[string]bool)
	for _, f := range findings {
		algos[f.Algorithm] = true
		t.Logf("[%s] %s at line %d: %s (lang: %s)", f.Severity, f.Algorithm, f.LineStart, f.Description, f.Language)
	}

	for _, want := range []string{"MD5", "SHA-1"} {
		if !algos[want] {
			t.Errorf("expected finding for %s", want)
		}
	}

	// Check RSA has key size enriched
	for _, f := range findings {
		if f.Algorithm == "RSA-2048" {
			if f.KeySize != 2048 {
				t.Errorf("expected key size 2048 for RSA, got %d", f.KeySize)
			}
			return
		}
	}
	t.Error("expected RSA-2048 finding with extracted modulusLength")
}

func TestAnalyzeFile_TypeScript(t *testing.T) {
	src := []byte(`import * as crypto from 'crypto';

const dh = crypto.createDiffieHellman(2048);
const ecdh = crypto.createECDH('secp256k1');
`)

	a := New()
	findings := a.AnalyzeFile("key_exchange.ts", src)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Language != "typescript" {
			t.Errorf("expected language typescript, got %s", f.Language)
		}
		if f.Severity != models.SeverityCritical {
			t.Errorf("expected CRITICAL severity for %s, got %s", f.Algorithm, f.Severity)
		}
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_WebCrypto(t *testing.T) {
	src := []byte(`const key = await crypto.subtle.generateKey({name:'RSA-OAEP', modulusLength:2048}, true, ['encrypt','decrypt']);
const ecKey = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify']);
`)

	a := New()
	findings := a.AnalyzeFile("web_crypto.js", src)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_ThirdParty(t *testing.T) {
	src := []byte(`const NodeRSA = require('node-rsa');
const key = new NodeRSA({b: 2048});

const forge = require('node-forge');
const keypair = forge.pki.rsa.generateKeyPair({bits: 4096});
`)

	a := New()
	findings := a.AnalyzeFile("third_party.js", src)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != models.SeverityCritical {
			t.Errorf("expected CRITICAL for %s, got %s", f.Algorithm, f.Severity)
		}
		t.Logf("[%s] %s (keySize=%d) at line %d: %s", f.Severity, f.Algorithm, f.KeySize, f.LineStart, f.Description)
	}
}

func TestAnalyzeFile_VariableTracking(t *testing.T) {
	src := []byte(`const crypto = require('crypto');
const algo = 'md5';
const hash = crypto.createHash(algo).update('data').digest('hex');
`)

	a := New()
	findings := a.AnalyzeFile("taint.js", src)

	found := false
	for _, f := range findings {
		if f.RuleID == "QS-JS-TAINT-001" {
			found = true
			if f.Confidence != 0.83 {
				t.Errorf("expected confidence 0.83, got %f", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected taint finding for md5 via variable")
	}
}

func TestAnalyzeFile_SkipsComments(t *testing.T) {
	src := []byte(`// crypto.createHash('md5')
/* crypto.generateKeyPairSync('rsa', {...}) */
* crypto.createDiffieHellman(2048)
`)

	a := New()
	findings := a.AnalyzeFile("comments.js", src)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for commented code, got %d", len(findings))
	}
}
