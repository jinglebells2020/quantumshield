package information

import (
	"crypto/rand"
	"math"
	mrand "math/rand"
	"testing"
)

func TestShannonEntropy_Uniform(t *testing.T) {
	freq := make(map[int]int)
	for i := 0; i < 256; i++ {
		freq[i] = 100
	}
	h := ShannonEntropy(freq, 25600)
	if math.Abs(h-8.0) > 0.01 {
		t.Errorf("uniform entropy = %.4f, want 8.0", h)
	}
}

func TestShannonEntropy_Constant(t *testing.T) {
	freq := map[int]int{0: 1000}
	h := ShannonEntropy(freq, 1000)
	if h != 0 {
		t.Errorf("constant entropy = %.4f, want 0.0", h)
	}
}

func TestKLDivergence_Identical(t *testing.T) {
	p := make([]float64, 10)
	for i := range p {
		p[i] = 0.1
	}
	kl := KLDivergence(p, p)
	if math.Abs(kl) > 1e-10 {
		t.Errorf("KL(P||P) = %.10f, want 0", kl)
	}
}

func TestKLDivergence_Divergent(t *testing.T) {
	p := []float64{0.5, 0.5}
	q := []float64{0.25, 0.75}
	kl := KLDivergence(p, q)
	// Hand-computed: 0.5*ln(0.5/0.25) + 0.5*ln(0.5/0.75) = 0.5*ln(2) + 0.5*ln(2/3) ≈ 0.1438
	if math.Abs(kl-0.14384) > 0.001 {
		t.Errorf("KL divergence = %.5f, want ~0.14384", kl)
	}
}

func TestNormalCDF(t *testing.T) {
	tests := []struct {
		x    float64
		want float64
	}{
		{0, 0.5},
		{-3, 0.00135},
		{3, 0.99865},
	}
	for _, tt := range tests {
		got := NormalCDF(tt.x)
		if math.Abs(got-tt.want) > 0.001 {
			t.Errorf("NormalCDF(%.1f) = %.5f, want ~%.5f", tt.x, got, tt.want)
		}
	}
}

func TestAssessCryptoOutput_GoodRandom(t *testing.T) {
	data := make([]byte, 100000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	es := NewEntropyScorer()
	a, err := es.AssessCryptoOutput(data, "crypto/rand")
	if err != nil {
		t.Fatal(err)
	}
	if a.ByteEntropy < 7.9 {
		t.Errorf("crypto/rand entropy = %.4f, want > 7.9", a.ByteEntropy)
	}
	if a.StrengthScore < 70 {
		t.Errorf("crypto/rand score = %.1f, want > 70", a.StrengthScore)
	}
	if !a.IsAcceptable {
		t.Errorf("crypto/rand should be acceptable, weaknesses: %v", a.Weaknesses)
	}
}

func TestAssessCryptoOutput_WeakRNG(t *testing.T) {
	rng := mrand.New(mrand.NewSource(42))
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(rng.Intn(256))
	}
	es := NewEntropyScorer()
	a, err := es.AssessCryptoOutput(data, "math/rand")
	if err != nil {
		t.Fatal(err)
	}
	// math/rand should still have decent entropy but may fail serial correlation
	if a.ByteEntropy < 7.0 {
		t.Errorf("math/rand entropy unexpectedly low: %.4f", a.ByteEntropy)
	}
}

func TestAssessCryptoOutput_ConstantOutput(t *testing.T) {
	data := make([]byte, 1000)
	es := NewEntropyScorer()
	a, err := es.AssessCryptoOutput(data, "zeros")
	if err != nil {
		t.Fatal(err)
	}
	if a.ByteEntropy > 0.01 {
		t.Errorf("constant output entropy = %.4f, want ~0", a.ByteEntropy)
	}
	if a.StrengthScore > 20 {
		t.Errorf("constant output score = %.1f, want < 20", a.StrengthScore)
	}
	if a.IsAcceptable {
		t.Error("constant output should not be acceptable")
	}
}

func TestAssessCryptoOutput_BiasedBytes(t *testing.T) {
	data := make([]byte, 5000)
	rng := mrand.New(mrand.NewSource(99))
	for i := range data {
		data[i] = byte(rng.Intn(128)) // biased toward low values
	}
	es := NewEntropyScorer()
	a, err := es.AssessCryptoOutput(data, "biased")
	if err != nil {
		t.Fatal(err)
	}
	if a.IsAcceptable {
		t.Error("biased output should not be acceptable")
	}
	if len(a.Weaknesses) == 0 {
		t.Error("biased output should have weaknesses")
	}
}

func TestChiSquaredTest_KnownDistribution(t *testing.T) {
	// Fair die rolled 600 times, expected 100 per face
	observed := []int{95, 103, 98, 107, 99, 98}
	expected := []float64{100, 100, 100, 100, 100, 100}
	chiSq, pVal := ChiSquaredTest(observed, expected)
	if chiSq < 0 {
		t.Errorf("chi-squared should be non-negative, got %.4f", chiSq)
	}
	// This should not reject H0 (fair die)
	if pVal < 0.01 {
		t.Errorf("fair die should not be rejected at 0.01, p=%.4f", pVal)
	}
}

func TestIncompleteGamma(t *testing.T) {
	// P(1, 1) = 1 - e^(-1) ≈ 0.6321
	got := IncompleteGamma(1, 1)
	if math.Abs(got-0.6321) > 0.001 {
		t.Errorf("IncompleteGamma(1,1) = %.4f, want ~0.6321", got)
	}
}

func TestMonoBitTest_Balanced(t *testing.T) {
	data := make([]byte, 1000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	p := MonoBitTest(data)
	if p < 0.01 {
		t.Errorf("random data should pass monobit, p=%.4f", p)
	}
}

func TestSerialCorrelation_Constant(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 42
	}
	r := SerialCorrelation(data)
	if math.IsNaN(r) {
		t.Error("serial correlation should not be NaN for constant data")
	}
}

func TestCompareImplementations(t *testing.T) {
	good := make([]byte, 5000)
	rand.Read(good)
	bad := make([]byte, 5000) // all zeros
	es := NewEntropyScorer()
	r, err := es.CompareImplementations(good, bad, "good", "bad")
	if err != nil {
		t.Fatal(err)
	}
	if r.StrongerImpl != "good" {
		t.Errorf("expected good to be stronger, got %s", r.StrongerImpl)
	}
}
