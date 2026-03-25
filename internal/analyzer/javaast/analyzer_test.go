package javaast

import (
	"testing"

	"quantumshield/pkg/models"
)

func TestAnalyzeFile_RSAEncrypt(t *testing.T) {
	src := []byte(`import java.security.*;
import javax.crypto.*;

public class RSAEncrypt {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest("test".getBytes());

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5hash = md5.digest("test".getBytes());
    }
}`)

	a := New()
	findings := a.AnalyzeFile("RSAEncrypt.java", src)

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should find: RSA KPG, RSA Cipher, SHA-1, MD5
	algos := make(map[string]bool)
	for _, f := range findings {
		algos[f.Algorithm] = true
		t.Logf("[%s] %s at line %d: %s", f.Severity, f.Algorithm, f.LineStart, f.Description)
	}

	for _, want := range []string{"RSA-2048", "SHA-1", "MD5"} {
		if !algos[want] {
			t.Errorf("expected finding for %s", want)
		}
	}
}

func TestAnalyzeFile_VariableTracking(t *testing.T) {
	src := []byte(`public class Test {
    void test() {
        String algo = "DES";
        Cipher c = Cipher.getInstance(algo);
    }
}`)

	a := New()
	findings := a.AnalyzeFile("Test.java", src)

	found := false
	for _, f := range findings {
		if f.RuleID == "QS-JAVA-TAINT-001" && f.Algorithm == "DES" {
			found = true
			if f.Confidence != 0.85 {
				t.Errorf("expected confidence 0.85, got %f", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected taint finding for DES via variable")
	}
}

func TestAnalyzeFile_SkipsComments(t *testing.T) {
	src := []byte(`public class Test {
    // Cipher.getInstance("DES")
    /* Cipher.getInstance("RSA") */
    void test() {}
}`)

	a := New()
	findings := a.AnalyzeFile("Test.java", src)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for commented code, got %d", len(findings))
	}
}

func TestAnalyzeFile_BouncyCastle(t *testing.T) {
	src := []byte(`public class BC {
    void test() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        ECKeyPairGenerator ecgen = new ECKeyPairGenerator();
    }
}`)

	a := New()
	findings := a.AnalyzeFile("BC.java", src)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Error("expected CRITICAL severity for Bouncy Castle RSA")
	}
}
