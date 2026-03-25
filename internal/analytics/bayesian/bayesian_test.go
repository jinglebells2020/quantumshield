package bayesian

import (
	"math"
	"testing"

	"quantumshield/pkg/models"
)

func almostEqual(a, b, tol float64) bool {
	return math.Abs(a-b) < tol
}

// ---------- bayesian.go tests ----------

func TestLogOddsRoundTrip(t *testing.T) {
	probabilities := []float64{0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99}
	for _, p := range probabilities {
		lo := LogOdds(p)
		got := FromLogOdds(lo)
		if !almostEqual(got, p, 1e-9) {
			t.Errorf("LogOdds round-trip failed for p=%f: got %f", p, got)
		}
	}
}

func TestLogOddsEdgeCases(t *testing.T) {
	if !math.IsInf(LogOdds(0), -1) {
		t.Error("LogOdds(0) should be -Inf")
	}
	if !math.IsInf(LogOdds(1), 1) {
		t.Error("LogOdds(1) should be +Inf")
	}
	if FromLogOdds(math.Inf(1)) != 1 {
		t.Error("FromLogOdds(+Inf) should be 1")
	}
	if FromLogOdds(math.Inf(-1)) != 0 {
		t.Error("FromLogOdds(-Inf) should be 0")
	}
}

func TestBetaUpdate(t *testing.T) {
	// Start with uniform prior Beta(1,1)
	a, b := 1.0, 1.0

	// After one success: Beta(2,1)
	a, b = BetaUpdate(a, b, true)
	if a != 2 || b != 1 {
		t.Errorf("after success: got alpha=%f beta=%f, want 2,1", a, b)
	}

	// After one failure: Beta(2,2)
	a, b = BetaUpdate(a, b, false)
	if a != 2 || b != 2 {
		t.Errorf("after failure: got alpha=%f beta=%f, want 2,2", a, b)
	}

	// Mean should be 0.5
	mean := BetaMean(a, b)
	if !almostEqual(mean, 0.5, 1e-9) {
		t.Errorf("BetaMean(2,2) = %f, want 0.5", mean)
	}
}

func TestBetaMean_ZeroParams(t *testing.T) {
	got := BetaMean(0, 0)
	if got != 0.5 {
		t.Errorf("BetaMean(0,0) = %f, want 0.5", got)
	}
}

// ---------- false_positive_reducer.go tests ----------

func TestComputePosterior_NeutralEvidence(t *testing.T) {
	r := NewFalsePositiveReducer()
	// No signals observed → posterior should stay close to prior.
	signals := []ContextSignal{}
	posterior := r.ComputePosterior(0.70, signals)
	if !almostEqual(posterior, 0.70, 1e-9) {
		t.Errorf("neutral evidence: posterior=%f, want ~0.70", posterior)
	}
}

func TestComputePosterior_StrongPositive(t *testing.T) {
	r := NewFalsePositiveReducer()

	// Build signals that strongly indicate a true vulnerability:
	// high severity, in dependency, called in production, NOT a test file.
	signals := []ContextSignal{
		{Name: "high_severity_rule", Observed: true, LikelihoodIfTrue: 0.80, LikelihoodIfFalse: 0.40},
		{Name: "in_dependency", Observed: true, LikelihoodIfTrue: 0.85, LikelihoodIfFalse: 0.30},
		{Name: "called_in_production_path", Observed: true, LikelihoodIfTrue: 0.90, LikelihoodIfFalse: 0.20},
	}

	prior := 0.70
	posterior := r.ComputePosterior(prior, signals)
	if posterior <= prior {
		t.Errorf("strong positive evidence: posterior=%f should be > prior=%f", posterior, prior)
	}
	if posterior < 0.95 {
		t.Errorf("strong positive evidence: posterior=%f should be >= 0.95", posterior)
	}
}

func TestComputePosterior_StrongNegative(t *testing.T) {
	r := NewFalsePositiveReducer()

	// Signals: test file, in comment, variable name contains test.
	signals := []ContextSignal{
		{Name: "is_test_file", Observed: true, LikelihoodIfTrue: 0.15, LikelihoodIfFalse: 0.60},
		{Name: "in_comment", Observed: true, LikelihoodIfTrue: 0.02, LikelihoodIfFalse: 0.30},
		{Name: "variable_name_contains_test", Observed: true, LikelihoodIfTrue: 0.05, LikelihoodIfFalse: 0.40},
	}

	prior := 0.70
	posterior := r.ComputePosterior(prior, signals)
	if posterior >= prior {
		t.Errorf("strong negative evidence: posterior=%f should be < prior=%f", posterior, prior)
	}
	if posterior >= 0.50 {
		t.Errorf("strong negative evidence: posterior=%f should be < 0.50", posterior)
	}
}

func TestComputePosterior_NumericalStability(t *testing.T) {
	r := NewFalsePositiveReducer()

	signals := []ContextSignal{
		{Name: "high_severity_rule", Observed: true, LikelihoodIfTrue: 0.80, LikelihoodIfFalse: 0.40},
		{Name: "in_dependency", Observed: true, LikelihoodIfTrue: 0.85, LikelihoodIfFalse: 0.30},
	}

	// Very high prior — should not produce NaN or >1.
	posterior := r.ComputePosterior(0.999, signals)
	if math.IsNaN(posterior) {
		t.Error("posterior is NaN for prior=0.999")
	}
	if posterior > 1 || posterior < 0 {
		t.Errorf("posterior=%f out of [0,1] for prior=0.999", posterior)
	}

	// Very low prior — should not produce NaN or <0.
	posterior = r.ComputePosterior(0.001, signals)
	if math.IsNaN(posterior) {
		t.Error("posterior is NaN for prior=0.001")
	}
	if posterior > 1 || posterior < 0 {
		t.Errorf("posterior=%f out of [0,1] for prior=0.001", posterior)
	}
}

func TestExtractSignals_TestFile(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:    "internal/crypto/aes_test.go",
		CodeSnippet: "aes.NewCipher(key)",
		Severity:    models.SeverityMedium,
	}

	signals := r.ExtractSignals(f)
	found := false
	for _, s := range signals {
		if s.Name == "is_test_file" {
			if !s.Observed {
				t.Error("is_test_file should be observed for _test.go file")
			}
			found = true
		}
	}
	if !found {
		t.Error("is_test_file signal not found in extracted signals")
	}
}

func TestExtractSignals_ProductionCode(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:    "internal/crypto/aes.go",
		CodeSnippet: "aes.NewCipher(key)",
		Severity:    models.SeverityHigh,
	}

	signals := r.ExtractSignals(f)
	for _, s := range signals {
		switch s.Name {
		case "called_in_production_path":
			if !s.Observed {
				t.Error("production path should be observed for non-test file")
			}
		case "is_test_file":
			if s.Observed {
				t.Error("is_test_file should NOT be observed for production file")
			}
		case "high_severity_rule":
			if !s.Observed {
				t.Error("high_severity_rule should be observed for SeverityHigh")
			}
		}
	}
}

func TestExtractSignals_Comment(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:    "internal/crypto/aes.go",
		CodeSnippet: "// aes.NewCipher(key) for encryption",
		Severity:    models.SeverityMedium,
	}

	signals := r.ExtractSignals(f)
	for _, s := range signals {
		if s.Name == "in_comment" && !s.Observed {
			t.Error("in_comment should be observed for snippet starting with //")
		}
	}
}

func TestExtractSignals_ExampleCode(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:    "examples/demo/encrypt.go",
		CodeSnippet: "rsa.GenerateKey(rand.Reader, 2048)",
		Severity:    models.SeverityMedium,
	}

	signals := r.ExtractSignals(f)
	for _, s := range signals {
		if s.Name == "in_example_code" && !s.Observed {
			t.Error("in_example_code should be observed for /examples/ path")
		}
	}
}

func TestExtractSignals_Deprecated(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:    "internal/legacy/rsa.go",
		CodeSnippet: "// Deprecated: use NewEncrypt instead",
		Severity:    models.SeverityLow,
	}

	signals := r.ExtractSignals(f)
	for _, s := range signals {
		if s.Name == "in_deprecated_block" && !s.Observed {
			t.Error("in_deprecated_block should be observed for deprecated snippet")
		}
	}
}

func TestExtractSignals_InDependency(t *testing.T) {
	r := NewFalsePositiveReducer()

	f := models.Finding{
		FilePath:     "vendor/github.com/foo/bar/crypto.go",
		CodeSnippet:  "des.NewCipher(key)",
		Severity:     models.SeverityHigh,
		InDependency: true,
	}

	signals := r.ExtractSignals(f)
	for _, s := range signals {
		if s.Name == "in_dependency" && !s.Observed {
			t.Error("in_dependency should be observed when InDependency=true")
		}
	}
}

func TestUpdatePriors(t *testing.T) {
	r := NewFalsePositiveReducer()

	ruleID := "RSA_WEAK_KEY"

	// Initial prior should be the default.
	initial := r.priorFor(ruleID)
	if !almostEqual(initial, 0.70, 1e-9) {
		t.Errorf("initial prior=%f, want 0.70", initial)
	}

	// Feed several true-positive confirmations; prior should increase.
	for i := 0; i < 10; i++ {
		r.UpdatePriors(ruleID, true)
	}
	afterTP := r.priorFor(ruleID)
	if afterTP <= initial {
		t.Errorf("after 10 TP updates: prior=%f should be > initial=%f", afterTP, initial)
	}

	// Now feed many false-positive feedbacks; prior should decrease.
	for i := 0; i < 30; i++ {
		r.UpdatePriors(ruleID, false)
	}
	afterFP := r.priorFor(ruleID)
	if afterFP >= afterTP {
		t.Errorf("after 30 FP updates: prior=%f should be < afterTP=%f", afterFP, afterTP)
	}

	// After heavy FP feedback, the prior should have dropped well below 0.5.
	if afterFP >= 0.50 {
		t.Errorf("after heavy FP feedback: prior=%f should be < 0.50", afterFP)
	}
}

func TestAssessAll_Sorting(t *testing.T) {
	r := NewFalsePositiveReducer()

	findings := []models.Finding{
		{
			// Low confidence: test file with test variable
			RuleID:      "DES_USAGE",
			FilePath:    "pkg/crypto/des_test.go",
			CodeSnippet: "testKey := des.NewCipher(mockKey)",
			Severity:    models.SeverityLow,
		},
		{
			// High confidence: production code, high severity, in dependency
			RuleID:       "RSA_1024",
			FilePath:     "internal/auth/rsa.go",
			CodeSnippet:  "rsa.GenerateKey(rand.Reader, 1024)",
			Severity:     models.SeverityHigh,
			InDependency: true,
		},
		{
			// Medium confidence: production code, medium severity
			RuleID:      "MD5_HASH",
			FilePath:    "internal/hash/md5.go",
			CodeSnippet: "md5.Sum(data)",
			Severity:    models.SeverityMedium,
		},
	}

	assessments := r.AssessAll(findings)

	if len(assessments) != 3 {
		t.Fatalf("expected 3 assessments, got %d", len(assessments))
	}

	// Verify descending order.
	for i := 1; i < len(assessments); i++ {
		if assessments[i].Posterior > assessments[i-1].Posterior {
			t.Errorf("assessments not sorted descending: [%d].Posterior=%f > [%d].Posterior=%f",
				i, assessments[i].Posterior, i-1, assessments[i-1].Posterior)
		}
	}

	// The RSA finding (production, high severity, dependency) should be first.
	if assessments[0].Finding.RuleID != "RSA_1024" {
		t.Errorf("expected RSA_1024 first, got %s", assessments[0].Finding.RuleID)
	}

	// The test-file finding should be last (lowest posterior).
	if assessments[2].Finding.RuleID != "DES_USAGE" {
		t.Errorf("expected DES_USAGE last, got %s", assessments[2].Finding.RuleID)
	}
}

func TestAssessFinding_DecisionThreshold(t *testing.T) {
	r := NewFalsePositiveReducer()

	// Production code with high severity should be classified as true positive.
	prodFinding := models.Finding{
		RuleID:       "AES_ECB",
		FilePath:     "internal/encrypt/ecb.go",
		CodeSnippet:  "cipher.NewECBEncrypter(block)",
		Severity:     models.SeverityHigh,
		InDependency: true,
	}

	assessment := r.AssessFinding(prodFinding)
	if !assessment.IsTruePositive {
		t.Errorf("production high-severity finding should be true positive, posterior=%f", assessment.Posterior)
	}

	// Test file with comment should likely be classified as false positive.
	testFinding := models.Finding{
		RuleID:      "DES_USAGE",
		FilePath:    "tests/crypto_test.go",
		CodeSnippet: "// testDES uses des.NewCipher(fakeKey)",
		Severity:    models.SeverityLow,
	}

	assessment = r.AssessFinding(testFinding)
	if assessment.IsTruePositive {
		t.Errorf("test comment finding should be false positive, posterior=%f", assessment.Posterior)
	}
}

func TestGetFilteredFindings(t *testing.T) {
	r := NewFalsePositiveReducer()

	findings := []models.Finding{
		{
			RuleID:       "RSA_1024",
			FilePath:     "internal/auth/rsa.go",
			CodeSnippet:  "rsa.GenerateKey(rand.Reader, 1024)",
			Severity:     models.SeverityHigh,
			InDependency: true,
		},
		{
			RuleID:      "DES_USAGE",
			FilePath:    "tests/crypto_test.go",
			CodeSnippet: "// testDES uses des.NewCipher(fakeKey)",
			Severity:    models.SeverityLow,
		},
	}

	filtered := r.GetFilteredFindings(findings)

	// The production finding should pass the filter; the test one should not.
	if len(filtered) < 1 {
		t.Fatal("expected at least 1 filtered finding")
	}

	for _, f := range filtered {
		if f.RuleID == "DES_USAGE" {
			t.Error("test-file finding should have been filtered out")
		}
	}
}

func TestWithOptions(t *testing.T) {
	r := NewFalsePositiveReducer(
		WithDefaultPrior(0.80),
		WithDecisionThreshold(0.60),
		WithRulePrior("CUSTOM_RULE", 0.90),
	)

	if !almostEqual(r.defaultPrior, 0.80, 1e-9) {
		t.Errorf("defaultPrior=%f, want 0.80", r.defaultPrior)
	}
	if !almostEqual(r.decisionThreshold, 0.60, 1e-9) {
		t.Errorf("decisionThreshold=%f, want 0.60", r.decisionThreshold)
	}
	if p, ok := r.rulePriors["CUSTOM_RULE"]; !ok || !almostEqual(p, 0.90, 1e-9) {
		t.Errorf("rulePrior for CUSTOM_RULE=%f, want 0.90", p)
	}
}
