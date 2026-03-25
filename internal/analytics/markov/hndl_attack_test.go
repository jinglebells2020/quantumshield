package markov

import (
	"math"
	"testing"

	"quantumshield/pkg/models"
)

func TestTransitionMatrixAtYear_2025(t *testing.T) {
	config := DefaultHNDLConfig()
	config.CRQCMidpointYear = 2032
	config.LogisticSteepness = 0.5
	analyzer := NewHNDLAnalyzer(config)

	T := analyzer.TransitionMatrixAtYear(2025)

	// p_quantum(2025) = 1/(1+exp(-0.5*(2025-2032))) = 1/(1+exp(3.5)) ~ 0.029
	pQuantum := 1.0 / (1.0 + math.Exp(-0.5*(2025.0-2032.0)))

	// Verify quantum probability is low (~0.03)
	if pQuantum > 0.05 {
		t.Errorf("p_quantum(2025) = %f, expected < 0.05", pQuantum)
	}

	// Harvested -> QuantumAvailable transition should match logistic
	if math.Abs(T[Harvested][QuantumAvailable]-pQuantum) > 1e-10 {
		t.Errorf("T[Harvested][QuantumAvailable] = %f, want %f",
			T[Harvested][QuantumAvailable], pQuantum)
	}

	// NotHarvested -> Harvested should match harvest probability
	if math.Abs(T[NotHarvested][Harvested]-config.HarvestProbability) > 1e-10 {
		t.Errorf("T[NotHarvested][Harvested] = %f, want %f",
			T[NotHarvested][Harvested], config.HarvestProbability)
	}

	// Exploited should be absorbing
	if T[Exploited][Exploited] != 1.0 {
		t.Errorf("T[Exploited][Exploited] = %f, want 1.0", T[Exploited][Exploited])
	}

	// Rows should sum to 1
	for i := 0; i < NumHNDLStates; i++ {
		rowSum := 0.0
		for j := 0; j < NumHNDLStates; j++ {
			rowSum += T[i][j]
		}
		if math.Abs(rowSum-1.0) > 1e-10 {
			t.Errorf("row %d sums to %f, want 1.0", i, rowSum)
		}
	}
}

func TestTransitionMatrixAtYear_2032(t *testing.T) {
	config := DefaultHNDLConfig()
	config.CRQCMidpointYear = 2032
	config.LogisticSteepness = 0.5
	analyzer := NewHNDLAnalyzer(config)

	T := analyzer.TransitionMatrixAtYear(2032)

	// p_quantum(2032) = 1/(1+exp(0)) = 0.5
	pQuantum := 1.0 / (1.0 + math.Exp(0))

	if math.Abs(pQuantum-0.5) > 1e-10 {
		t.Errorf("p_quantum(2032) = %f, expected 0.5", pQuantum)
	}

	if math.Abs(T[Harvested][QuantumAvailable]-0.5) > 1e-10 {
		t.Errorf("T[Harvested][QuantumAvailable] = %f, want 0.5",
			T[Harvested][QuantumAvailable])
	}

	// At midpoint, the Harvested self-loop should also be 0.5
	if math.Abs(T[Harvested][Harvested]-0.5) > 1e-10 {
		t.Errorf("T[Harvested][Harvested] = %f, want 0.5",
			T[Harvested][Harvested])
	}
}

func TestTransitionMatrixAtYear_2040(t *testing.T) {
	config := DefaultHNDLConfig()
	config.CRQCMidpointYear = 2032
	config.LogisticSteepness = 0.5
	analyzer := NewHNDLAnalyzer(config)

	T := analyzer.TransitionMatrixAtYear(2040)

	// p_quantum(2040) = 1/(1+exp(-0.5*(2040-2032))) = 1/(1+exp(-4)) ~ 0.982
	pQuantum := 1.0 / (1.0 + math.Exp(-0.5*(2040.0-2032.0)))

	if pQuantum < 0.95 {
		t.Errorf("p_quantum(2040) = %f, expected > 0.95", pQuantum)
	}

	if math.Abs(T[Harvested][QuantumAvailable]-pQuantum) > 1e-10 {
		t.Errorf("T[Harvested][QuantumAvailable] = %f, want %f",
			T[Harvested][QuantumAvailable], pQuantum)
	}

	// Self-loop probability should be very small
	if T[Harvested][Harvested] > 0.05 {
		t.Errorf("T[Harvested][Harvested] = %f, expected < 0.05",
			T[Harvested][Harvested])
	}
}

func TestAnalyze_ShorVulnHighValueData(t *testing.T) {
	finding := models.Finding{
		Severity:      models.SeverityCritical,
		QuantumThreat: models.ThreatBrokenByShor,
		Category:      models.CategoryAsymmetricEncryption,
		Algorithm:     "RSA-2048",
	}

	analysis := AnalyzeFinding(finding, 15)

	// With Shor vulnerability + high value data + long retention:
	// should be critical risk
	if analysis.RiskLevel != "CRITICAL" && analysis.RiskLevel != "HIGH" {
		t.Errorf("risk level = %s, want CRITICAL or HIGH for Shor-vulnerable high-value data",
			analysis.RiskLevel)
	}

	// Peak exploit probability should be significant
	if analysis.PeakExploitProb < 0.3 {
		t.Errorf("peak exploit prob = %f, expected >= 0.3 for Shor-vulnerable",
			analysis.PeakExploitProb)
	}

	// Should have yearly states
	if len(analysis.YearlyStates) == 0 {
		t.Error("analysis should have yearly states")
	}

	// Expected exploit year should be reasonable
	if analysis.ExpectedExploitYear < 2025 || analysis.ExpectedExploitYear > 2060 {
		t.Errorf("expected exploit year = %d, want in [2025, 2060]",
			analysis.ExpectedExploitYear)
	}
}

func TestAnalyze_ShortRetention(t *testing.T) {
	finding := models.Finding{
		Severity:      models.SeverityMedium,
		QuantumThreat: models.ThreatWeakenedByGrover,
		Category:      models.CategorySymmetricEncryption,
		Algorithm:     "AES-128",
	}

	// Very short retention: data becomes worthless before quantum threat
	analysis := AnalyzeFinding(finding, 2)

	// With Grover (0.3 factor) + short retention + reduced data value:
	// risk should be low
	if analysis.RiskLevel != "LOW" && analysis.RiskLevel != "MEDIUM" {
		t.Errorf("risk level = %s, want LOW or MEDIUM for short-retention Grover-weakened",
			analysis.RiskLevel)
	}

	// Peak exploit probability should be low
	if analysis.PeakExploitProb > 0.3 {
		t.Errorf("peak exploit prob = %f, expected <= 0.3 for short retention",
			analysis.PeakExploitProb)
	}
}

func TestAnalyze_ExploitProbMonotonicallyIncreases(t *testing.T) {
	config := DefaultHNDLConfig()
	config.VulnerabilityFactor = 1.0
	config.DataValueFactor = 0.8
	config.HarvestProbability = 0.15
	config.AnalysisStartYear = 2025
	config.AnalysisEndYear = 2045

	analyzer := NewHNDLAnalyzer(config)
	analysis := analyzer.Analyze()

	// P(exploited) should monotonically increase since Exploited is absorbing
	prevExploitProb := 0.0
	for i, ys := range analysis.YearlyStates {
		if ys.PExploited < prevExploitProb-1e-10 {
			t.Errorf("year %d: P(exploited) = %f < previous %f (non-monotonic at index %d)",
				ys.Year, ys.PExploited, prevExploitProb, i)
		}
		prevExploitProb = ys.PExploited
	}

	// First year should have P(exploited) = 0 (starts at NotHarvested)
	if analysis.YearlyStates[0].PExploited > 1e-10 {
		t.Errorf("year 0: P(exploited) = %f, want 0",
			analysis.YearlyStates[0].PExploited)
	}

	// Far enough out, P(exploited) should be substantial
	lastState := analysis.YearlyStates[len(analysis.YearlyStates)-1]
	if lastState.PExploited < 0.1 {
		t.Errorf("final year P(exploited) = %f, expected > 0.1", lastState.PExploited)
	}
}

func TestAnalyze_NotThreatened(t *testing.T) {
	finding := models.Finding{
		Severity:      models.SeverityLow,
		QuantumThreat: models.ThreatNotDirectlyThreatened,
		Category:      models.CategoryHashing,
		Algorithm:     "SHA-256",
	}

	analysis := AnalyzeFinding(finding, 10)

	// With vulnerability factor 0, quantum computers can't break this
	// so P(exploited) should stay 0 or near 0
	for _, ys := range analysis.YearlyStates {
		if ys.PExploited > 1e-6 {
			t.Errorf("year %d: P(exploited) = %f, expected ~0 for non-threatened algorithm",
				ys.Year, ys.PExploited)
		}
	}

	if analysis.RiskLevel != "LOW" {
		t.Errorf("risk level = %s, want LOW for non-threatened algorithm", analysis.RiskLevel)
	}
}

func TestAnalyze_YearlyStateConsistency(t *testing.T) {
	config := DefaultHNDLConfig()
	config.AnalysisStartYear = 2025
	config.AnalysisEndYear = 2040

	analyzer := NewHNDLAnalyzer(config)
	analysis := analyzer.Analyze()

	// Each year's state distribution should sum to 1
	for _, ys := range analysis.YearlyStates {
		sum := 0.0
		for s := 0; s < NumHNDLStates; s++ {
			sum += ys.StateDistribution[s]
		}
		if math.Abs(sum-1.0) > 1e-8 {
			t.Errorf("year %d: state distribution sums to %f, want 1.0", ys.Year, sum)
		}

		// All probabilities should be non-negative
		for s := 0; s < NumHNDLStates; s++ {
			if ys.StateDistribution[s] < -1e-10 {
				t.Errorf("year %d state %d: negative probability %f",
					ys.Year, s, ys.StateDistribution[s])
			}
		}
	}

	// Years should be in order
	for i := 1; i < len(analysis.YearlyStates); i++ {
		if analysis.YearlyStates[i].Year <= analysis.YearlyStates[i-1].Year {
			t.Errorf("years not in order at index %d: %d <= %d",
				i, analysis.YearlyStates[i].Year, analysis.YearlyStates[i-1].Year)
		}
	}
}
