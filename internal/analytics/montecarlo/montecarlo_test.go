package montecarlo

import (
	"math"
	"testing"

	"quantumshield/pkg/models"
)

func TestSampleLogNormal_MeanStd(t *testing.T) {
	sim := NewMigrationSimulator(123)

	mu := 1.0
	sigma := 0.5
	n := 100000

	samples := make([]float64, n)
	for i := 0; i < n; i++ {
		samples[i] = sim.SampleLogNormal(mu, sigma)
	}

	// Theoretical mean of LogNormal: E[X] = exp(mu + sigma^2/2)
	expectedMean := math.Exp(mu + sigma*sigma/2.0)
	sampleMean := mean(samples)

	relErr := math.Abs(sampleMean-expectedMean) / expectedMean
	if relErr > 0.05 {
		t.Errorf("LogNormal mean: expected %.4f, got %.4f (rel error %.4f > 0.05)",
			expectedMean, sampleMean, relErr)
	}
}

func TestSampleExponential_Mean(t *testing.T) {
	sim := NewMigrationSimulator(456)

	expectedMean := 5.0
	n := 100000

	samples := make([]float64, n)
	for i := 0; i < n; i++ {
		samples[i] = sim.SampleExponential(expectedMean)
	}

	sampleMean := mean(samples)
	relErr := math.Abs(sampleMean-expectedMean) / expectedMean
	if relErr > 0.05 {
		t.Errorf("Exponential mean: expected %.4f, got %.4f (rel error %.4f > 0.05)",
			expectedMean, sampleMean, relErr)
	}
}

func TestPercentile_Known(t *testing.T) {
	data := []float64{1, 2, 3, 4, 5}
	p50 := Percentile(data, 50)

	if p50 != 3.0 {
		t.Errorf("Percentile(50) of [1,2,3,4,5]: expected 3.0, got %.4f", p50)
	}

	// Edge cases.
	p0 := Percentile(data, 0)
	if p0 != 1.0 {
		t.Errorf("Percentile(0): expected 1.0, got %.4f", p0)
	}

	p100 := Percentile(data, 100)
	if p100 != 5.0 {
		t.Errorf("Percentile(100): expected 5.0, got %.4f", p100)
	}

	// Empty slice.
	pEmpty := Percentile([]float64{}, 50)
	if pEmpty != 0 {
		t.Errorf("Percentile of empty: expected 0, got %.4f", pEmpty)
	}
}

func TestSimulate_Deterministic(t *testing.T) {
	findings := make([]models.Finding, 5)
	for i := range findings {
		findings[i] = models.Finding{
			ID:               "F" + string(rune('1'+i)),
			Algorithm:        "RSA-2048",
			Severity:         models.SeverityHigh,
			AutoFixAvailable: true,
			InDependency:     false,
		}
	}

	cfg := MigrationSimConfig{
		Findings:       findings,
		NumSimulations: 1000,
		RegressionProb: 0, // no regressions for deterministic behavior
	}

	r1 := cfg.Simulate()
	r2 := cfg.Simulate()

	// With fixed seed (42) and no regressions, results should be identical.
	if r1.MeanWeeks != r2.MeanWeeks {
		t.Errorf("Deterministic simulation: run1 mean=%.6f != run2 mean=%.6f",
			r1.MeanWeeks, r2.MeanWeeks)
	}
	if r1.MedianWeeks != r2.MedianWeeks {
		t.Errorf("Deterministic simulation: run1 median=%.6f != run2 median=%.6f",
			r1.MedianWeeks, r2.MedianWeeks)
	}

	// Sanity: mean should be positive.
	if r1.MeanWeeks <= 0 {
		t.Errorf("Expected positive mean weeks, got %.6f", r1.MeanWeeks)
	}
	if r1.MeanCost <= 0 {
		t.Errorf("Expected positive mean cost, got %.6f", r1.MeanCost)
	}
}

func TestSimulate_CDFMonotonic(t *testing.T) {
	findings := []models.Finding{
		{ID: "F1", AutoFixAvailable: true},
		{ID: "F2", AutoFixAvailable: false},
		{ID: "F3", InDependency: true},
	}

	cfg := MigrationSimConfig{
		Findings:       findings,
		NumSimulations: 2000,
	}
	result := cfg.Simulate()

	// CDF values must be non-decreasing.
	prevProb := 0.0
	maxWeek := 0
	for w := range result.WeeklyCompletionCDF {
		if w > maxWeek {
			maxWeek = w
		}
	}
	for w := 1; w <= maxWeek; w++ {
		prob, ok := result.WeeklyCompletionCDF[w]
		if !ok {
			continue
		}
		if prob < prevProb {
			t.Errorf("CDF not monotonic at week %d: %.4f < %.4f", w, prob, prevProb)
		}
		prevProb = prob
	}

	// Last CDF entry should be 1.0.
	if lastProb := result.WeeklyCompletionCDF[maxWeek]; lastProb != 1.0 {
		t.Errorf("CDF at max week %d should be 1.0, got %.4f", maxWeek, lastProb)
	}
}

func TestSimulate_HighRegression(t *testing.T) {
	findings := make([]models.Finding, 10)
	for i := range findings {
		findings[i] = models.Finding{
			ID:               "F" + string(rune('A'+i)),
			AutoFixAvailable: false,
		}
	}

	// Baseline: no regressions.
	baselineCfg := MigrationSimConfig{
		Findings:       findings,
		NumSimulations: 3000,
		RegressionProb: 0,
	}
	baseline := baselineCfg.Simulate()

	// High regression scenario.
	highRegCfg := MigrationSimConfig{
		Findings:       findings,
		NumSimulations: 3000,
		RegressionProb: 0.5,
	}
	highReg := highRegCfg.Simulate()

	if highReg.MeanWeeks <= baseline.MeanWeeks {
		t.Errorf("High regression (p=0.5) mean %.4f should exceed baseline mean %.4f",
			highReg.MeanWeeks, baseline.MeanWeeks)
	}

	if highReg.TotalRegressions <= 0 {
		t.Errorf("Expected positive regression count with p=0.5, got %.4f",
			highReg.TotalRegressions)
	}
}

func TestSensitivityAnalysis(t *testing.T) {
	findings := make([]models.Finding, 8)
	for i := range findings {
		findings[i] = models.Finding{
			ID:               "S" + string(rune('1'+i)),
			AutoFixAvailable: i%2 == 0,
			InDependency:     i%3 == 0,
		}
	}

	cfg := MigrationSimConfig{
		Findings:       findings,
		NumSimulations: 500, // fewer sims for test speed
	}

	result := cfg.SensitivityAnalysis()

	if len(result.Parameters) != 4 {
		t.Fatalf("Expected 4 sensitivity parameters, got %d", len(result.Parameters))
	}

	// Check all parameters are ranked and have non-negative sensitivity.
	seenNames := make(map[string]bool)
	for i, p := range result.Parameters {
		if p.SensitivityIndex < 0 {
			t.Errorf("Parameter %q has negative sensitivity index: %.6f", p.Name, p.SensitivityIndex)
		}
		if seenNames[p.Name] {
			t.Errorf("Duplicate parameter name: %q", p.Name)
		}
		seenNames[p.Name] = true

		// Verify sorted descending.
		if i > 0 && p.SensitivityIndex > result.Parameters[i-1].SensitivityIndex {
			t.Errorf("Parameters not sorted by sensitivity: [%d]=%f > [%d]=%f",
				i, p.SensitivityIndex, i-1, result.Parameters[i-1].SensitivityIndex)
		}
	}

	expectedParams := []string{"AutoFixMean", "ManualFixMean", "DepUpdateMeanDays", "RegressionProb"}
	for _, name := range expectedParams {
		if !seenNames[name] {
			t.Errorf("Missing expected parameter: %q", name)
		}
	}
}
