package information

import (
	"fmt"
	"math"
)

// CryptoStrengthAssessment is the output of analyzing cryptographic output quality.
type CryptoStrengthAssessment struct {
	Algorithm         string   `json:"algorithm"`
	SampleSize        int      `json:"sample_size_bytes"`
	ByteEntropy       float64  `json:"byte_entropy"`
	BigramEntropy     float64  `json:"bigram_entropy"`
	KLDiv             float64  `json:"kl_divergence"`
	ChiSquaredStat    float64  `json:"chi_squared_statistic"`
	ChiSquaredPValue  float64  `json:"chi_squared_p_value"`
	SerialCorr        float64  `json:"serial_correlation"`
	RunsTestPValue    float64  `json:"runs_test_p_value"`
	MonoBitPVal       float64  `json:"mono_bit_p_value"`
	StrengthScore     float64  `json:"strength_score"`
	Weaknesses        []string `json:"weaknesses"`
	IsAcceptable      bool     `json:"is_acceptable"`
}

// ComparisonResult compares two crypto implementations.
type ComparisonResult struct {
	AssessmentA     CryptoStrengthAssessment `json:"assessment_a"`
	AssessmentB     CryptoStrengthAssessment `json:"assessment_b"`
	StrongerImpl    string                   `json:"stronger_implementation"`
	ScoreDifference float64                  `json:"score_difference"`
	Conclusion      string                   `json:"conclusion"`
}

// EntropyScorerOption configures the EntropyScorer.
type EntropyScorerOption func(*EntropyScorer)

// WithSignificanceLevel sets the p-value threshold.
func WithSignificanceLevel(level float64) EntropyScorerOption {
	return func(es *EntropyScorer) {
		es.significanceLevel = level
	}
}

// EntropyScorer assesses cryptographic output quality using information-theoretic measures.
type EntropyScorer struct {
	significanceLevel float64
}

// NewEntropyScorer creates a scorer with configurable parameters.
func NewEntropyScorer(opts ...EntropyScorerOption) *EntropyScorer {
	es := &EntropyScorer{significanceLevel: 0.01}
	for _, o := range opts {
		o(es)
	}
	return es
}

// AssessCryptoOutput runs the full statistical test suite on cryptographic output bytes.
func (es *EntropyScorer) AssessCryptoOutput(data []byte, algorithm string) (*CryptoStrengthAssessment, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("need at least 32 bytes, got %d", len(data))
	}

	a := &CryptoStrengthAssessment{
		Algorithm:  algorithm,
		SampleSize: len(data),
	}

	// 1. Byte-level Shannon entropy
	byteFreq := make(map[int]int)
	for _, b := range data {
		byteFreq[int(b)]++
	}
	a.ByteEntropy = ShannonEntropy(byteFreq, len(data))

	// 2. Bigram-level Shannon entropy
	if len(data) >= 2 {
		bigramFreq := make(map[int]int)
		for i := 0; i < len(data)-1; i++ {
			key := int(data[i])<<8 | int(data[i+1])
			bigramFreq[key]++
		}
		a.BigramEntropy = ShannonEntropy(bigramFreq, len(data)-1)
	}

	// 3. KL divergence from uniform
	observed := make([]float64, 256)
	for b, c := range byteFreq {
		observed[b] = float64(c) / float64(len(data))
	}
	uniform := make([]float64, 256)
	for i := range uniform {
		uniform[i] = 1.0 / 256.0
	}
	a.KLDiv = KLDivergence(observed, uniform)

	// 4. Chi-squared test
	obs := make([]int, 256)
	exp := make([]float64, 256)
	expectedPerBin := float64(len(data)) / 256.0
	for i := 0; i < 256; i++ {
		obs[i] = byteFreq[i]
		exp[i] = expectedPerBin
	}
	a.ChiSquaredStat, a.ChiSquaredPValue = ChiSquaredTest(obs, exp)

	// 5. Serial correlation
	a.SerialCorr = SerialCorrelation(data)

	// 6. Runs test
	_, a.RunsTestPValue = WaldWolfowitzRunsTest(data)

	// 7. Monobit test
	a.MonoBitPVal = MonoBitTest(data)

	// 8. Composite strength score
	entropyPenalty := 50 * math.Abs(a.ByteEntropy-8.0) / 8.0
	klPenalty := 20 * math.Min(a.KLDiv*100, 1.0)
	corrPenalty := 15 * math.Abs(a.SerialCorr)
	chiPenalty := 15.0
	if a.ChiSquaredPValue > 0 {
		chiPenalty = 15 * (1 - a.ChiSquaredPValue)
	}
	a.StrengthScore = 100 - entropyPenalty - klPenalty - corrPenalty - chiPenalty
	if a.StrengthScore < 0 {
		a.StrengthScore = 0
	}
	if a.StrengthScore > 100 {
		a.StrengthScore = 100
	}

	// 9. Detect weaknesses
	if a.ByteEntropy < 7.5 {
		a.Weaknesses = append(a.Weaknesses, fmt.Sprintf("low byte entropy: %.2f bits (ideal: 8.0)", a.ByteEntropy))
	}
	if a.KLDiv > 0.01 {
		a.Weaknesses = append(a.Weaknesses, fmt.Sprintf("high KL divergence from uniform: %.4f", a.KLDiv))
	}
	if math.Abs(a.SerialCorr) > 0.05 {
		a.Weaknesses = append(a.Weaknesses, fmt.Sprintf("serial correlation detected: %.4f", a.SerialCorr))
	}
	if a.ChiSquaredPValue < es.significanceLevel {
		a.Weaknesses = append(a.Weaknesses, "chi-squared test rejects uniformity")
	}
	if a.RunsTestPValue < es.significanceLevel {
		a.Weaknesses = append(a.Weaknesses, "runs test rejects randomness")
	}
	if a.MonoBitPVal < es.significanceLevel {
		a.Weaknesses = append(a.Weaknesses, "monobit test detects bit bias")
	}

	// 10. Acceptability
	a.IsAcceptable = a.ChiSquaredPValue > es.significanceLevel &&
		a.RunsTestPValue > es.significanceLevel &&
		a.MonoBitPVal > es.significanceLevel &&
		a.KLDiv < 0.01 &&
		a.ByteEntropy > 7.9

	return a, nil
}

// CompareImplementations compares two crypto implementations.
func (es *EntropyScorer) CompareImplementations(dataA, dataB []byte, nameA, nameB string) (*ComparisonResult, error) {
	aa, err := es.AssessCryptoOutput(dataA, nameA)
	if err != nil {
		return nil, fmt.Errorf("assessing %s: %w", nameA, err)
	}
	ab, err := es.AssessCryptoOutput(dataB, nameB)
	if err != nil {
		return nil, fmt.Errorf("assessing %s: %w", nameB, err)
	}
	r := &ComparisonResult{
		AssessmentA:     *aa,
		AssessmentB:     *ab,
		ScoreDifference: aa.StrengthScore - ab.StrengthScore,
	}
	if aa.StrengthScore > ab.StrengthScore {
		r.StrongerImpl = nameA
		r.Conclusion = fmt.Sprintf("%s is stronger by %.1f points", nameA, r.ScoreDifference)
	} else if ab.StrengthScore > aa.StrengthScore {
		r.StrongerImpl = nameB
		r.Conclusion = fmt.Sprintf("%s is stronger by %.1f points", nameB, -r.ScoreDifference)
	} else {
		r.StrongerImpl = "equivalent"
		r.Conclusion = "implementations are statistically equivalent"
	}
	return r, nil
}
