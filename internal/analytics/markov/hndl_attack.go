package markov

import (
	"math"
	"time"

	"quantumshield/pkg/models"
)

// NumHNDLStates is the number of states in the HNDL attack lifecycle model.
const NumHNDLStates = 5

// HNDL (Harvest Now, Decrypt Later) attack lifecycle states.
const (
	// NotHarvested: data has not yet been intercepted by adversaries.
	NotHarvested = iota
	// Harvested: data has been intercepted and stored by adversaries.
	Harvested
	// QuantumAvailable: a cryptographically-relevant quantum computer is available.
	QuantumAvailable
	// Decrypted: harvested data has been decrypted using quantum computing.
	Decrypted
	// Exploited: decrypted data has been used for malicious purposes.
	Exploited
)

// HNDLStateName returns a human-readable label for an HNDL state.
func HNDLStateName(state int) string {
	switch state {
	case NotHarvested:
		return "NotHarvested"
	case Harvested:
		return "Harvested"
	case QuantumAvailable:
		return "QuantumAvailable"
	case Decrypted:
		return "Decrypted"
	case Exploited:
		return "Exploited"
	default:
		return "Unknown"
	}
}

// HNDLConfig contains the parameters for the HNDL attack lifecycle model.
type HNDLConfig struct {
	// HarvestProbability is the per-year probability of data being harvested.
	// Default: 0.15
	HarvestProbability float64

	// CRQCMidpointYear is the year at which there is a 50% chance of a
	// cryptographically-relevant quantum computer being available.
	// Default: 2032
	CRQCMidpointYear float64

	// LogisticSteepness controls how sharply the quantum availability
	// probability transitions from low to high around CRQCMidpointYear.
	// Default: 0.5
	LogisticSteepness float64

	// VulnerabilityFactor is the probability that a quantum computer can
	// decrypt the specific algorithm used (1.0 for Shor-vulnerable, 0.3 for Grover).
	// Default: 1.0
	VulnerabilityFactor float64

	// DataValueFactor scales the probability of exploitation given decryption.
	// Higher values indicate more valuable/sensitive data.
	// Default: 0.8
	DataValueFactor float64

	// DataRetentionYears is how long the data remains valuable if decrypted.
	// Default: 10
	DataRetentionYears int

	// AnalysisStartYear is the first year of the analysis window.
	// Default: current year
	AnalysisStartYear int

	// AnalysisEndYear is the last year of the analysis window.
	// Default: 2040
	AnalysisEndYear int
}

// DefaultHNDLConfig returns an HNDLConfig with sensible defaults.
func DefaultHNDLConfig() HNDLConfig {
	return HNDLConfig{
		HarvestProbability:  0.15,
		CRQCMidpointYear:   2032,
		LogisticSteepness:   0.5,
		VulnerabilityFactor: 1.0,
		DataValueFactor:     0.8,
		DataRetentionYears:  10,
		AnalysisStartYear:   time.Now().Year(),
		AnalysisEndYear:     2040,
	}
}

// HNDLYearState captures the state distribution and key probabilities at a given year.
type HNDLYearState struct {
	Year              int
	StateDistribution [NumHNDLStates]float64
	PExploited        float64
	PHarvested        float64
	PQuantumAvailable float64
}

// HNDLAnalysis contains the complete output of the HNDL attack lifecycle analysis.
type HNDLAnalysis struct {
	Config             HNDLConfig
	YearlyStates       []HNDLYearState
	PeakExploitProb    float64
	ExpectedExploitYear int
	RiskLevel          string
	CumulativeRisk     float64
}

// HNDLAnalyzer performs HNDL attack lifecycle analysis using a time-varying
// Markov chain model.
type HNDLAnalyzer struct {
	config HNDLConfig
}

// NewHNDLAnalyzer creates an analyzer with the given configuration.
func NewHNDLAnalyzer(config HNDLConfig) *HNDLAnalyzer {
	return &HNDLAnalyzer{config: config}
}

// TransitionMatrixAtYear constructs the HNDL transition matrix for a given year.
// The quantum availability probability follows a logistic function:
//
//	p_quantum(t) = 1 / (1 + exp(-k * (t - t_mid)))
//
// where k is the steepness and t_mid is the CRQC midpoint year.
func (a *HNDLAnalyzer) TransitionMatrixAtYear(year int) [NumHNDLStates][NumHNDLStates]float64 {
	t := float64(year)
	k := a.config.LogisticSteepness
	tMid := a.config.CRQCMidpointYear

	// Logistic function for quantum availability
	pQuantum := 1.0 / (1.0 + math.Exp(-k*(t-tMid)))

	pHarvest := a.config.HarvestProbability
	pDecrypt := pQuantum * a.config.VulnerabilityFactor
	pExploit := a.config.DataValueFactor

	// Clamp probabilities to [0, 1]
	pHarvest = math.Min(math.Max(pHarvest, 0), 1)
	pDecrypt = math.Min(math.Max(pDecrypt, 0), 1)
	pExploit = math.Min(math.Max(pExploit, 0), 1)

	var T [NumHNDLStates][NumHNDLStates]float64

	// NotHarvested -> can be harvested or stay
	T[NotHarvested][NotHarvested] = 1.0 - pHarvest
	T[NotHarvested][Harvested] = pHarvest

	// Harvested -> can become quantum-available or stay
	T[Harvested][Harvested] = 1.0 - pQuantum
	T[Harvested][QuantumAvailable] = pQuantum

	// QuantumAvailable -> can be decrypted or stay
	T[QuantumAvailable][QuantumAvailable] = 1.0 - pDecrypt
	T[QuantumAvailable][Decrypted] = pDecrypt

	// Decrypted -> can be exploited or stay
	T[Decrypted][Decrypted] = 1.0 - pExploit
	T[Decrypted][Exploited] = pExploit

	// Exploited is an absorbing state
	T[Exploited][Exploited] = 1.0

	return T
}

// Analyze runs the full HNDL attack lifecycle analysis across the configured
// year range. Starts with the initial distribution pi_0 = [1, 0, 0, 0, 0]
// (all data not yet harvested) and iterates year by year, applying the
// time-varying transition matrix.
func (a *HNDLAnalyzer) Analyze() *HNDLAnalysis {
	// Initial state: all probability in NotHarvested
	var pi [NumHNDLStates]float64
	pi[NotHarvested] = 1.0

	startYear := a.config.AnalysisStartYear
	endYear := a.config.AnalysisEndYear
	if endYear <= startYear {
		endYear = startYear + 15
	}

	yearlyStates := make([]HNDLYearState, 0, endYear-startYear+1)

	peakExploitProb := 0.0
	expectedExploitYear := 0
	cumulativeRisk := 0.0
	weightedYearSum := 0.0
	exploitProbSum := 0.0

	// Record initial state
	yearlyStates = append(yearlyStates, HNDLYearState{
		Year:              startYear,
		StateDistribution: pi,
		PExploited:        pi[Exploited],
		PHarvested:        pi[Harvested] + pi[QuantumAvailable] + pi[Decrypted] + pi[Exploited],
		PQuantumAvailable: 0,
	})

	for year := startYear + 1; year <= endYear; year++ {
		T := a.TransitionMatrixAtYear(year)

		// Multiply pi by T (pi is a row vector)
		var next [NumHNDLStates]float64
		for j := 0; j < NumHNDLStates; j++ {
			sum := 0.0
			for i := 0; i < NumHNDLStates; i++ {
				sum += pi[i] * T[i][j]
			}
			next[j] = sum
		}
		pi = next

		// Compute quantum availability probability for this year
		pQ := 1.0 / (1.0 + math.Exp(-a.config.LogisticSteepness*(float64(year)-a.config.CRQCMidpointYear)))

		yearState := HNDLYearState{
			Year:              year,
			StateDistribution: pi,
			PExploited:        pi[Exploited],
			PHarvested:        pi[Harvested] + pi[QuantumAvailable] + pi[Decrypted] + pi[Exploited],
			PQuantumAvailable: pQ,
		}
		yearlyStates = append(yearlyStates, yearState)

		// Track peak exploit probability
		if pi[Exploited] > peakExploitProb {
			peakExploitProb = pi[Exploited]
		}

		// Accumulate for expected exploit year calculation
		// Marginal increase in exploit probability this year
		prevExploited := 0.0
		if len(yearlyStates) >= 2 {
			prevExploited = yearlyStates[len(yearlyStates)-2].PExploited
		}
		marginalExploit := pi[Exploited] - prevExploited
		if marginalExploit > 0 {
			weightedYearSum += float64(year) * marginalExploit
			exploitProbSum += marginalExploit
		}

		cumulativeRisk += pi[Exploited]
	}

	// Expected exploit year
	if exploitProbSum > 0 {
		expectedExploitYear = int(math.Round(weightedYearSum / exploitProbSum))
	}

	// Risk level classification
	riskLevel := classifyHNDLRisk(peakExploitProb)

	// Normalize cumulative risk
	numYears := float64(endYear - startYear)
	if numYears > 0 {
		cumulativeRisk /= numYears
	}

	return &HNDLAnalysis{
		Config:              a.config,
		YearlyStates:        yearlyStates,
		PeakExploitProb:     peakExploitProb,
		ExpectedExploitYear: expectedExploitYear,
		RiskLevel:           riskLevel,
		CumulativeRisk:      cumulativeRisk,
	}
}

// classifyHNDLRisk maps peak exploitation probability to a risk level string.
func classifyHNDLRisk(peakExploitProb float64) string {
	switch {
	case peakExploitProb >= 0.7:
		return "CRITICAL"
	case peakExploitProb >= 0.4:
		return "HIGH"
	case peakExploitProb >= 0.15:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// AnalyzeFinding creates an HNDLAnalyzer configured for a specific finding
// and runs the analysis. Infers vulnerability factor and data value from
// the finding's properties.
//
// Vulnerability factor by quantum threat:
//   - BrokenByShor: 1.0 (fully broken by Shor's algorithm)
//   - WeakenedByGrover: 0.3 (reduced security margin)
//   - NotThreatened: 0.0
//
// Data value factor by algorithm category:
//   - AsymmetricEncryption, KeyExchange: 0.9 (protects data in transit)
//   - DigitalSignature, Certificate: 0.7 (integrity/authenticity)
//   - SymmetricEncryption: 0.6 (Grover only halves key strength)
//   - Other: 0.5
func AnalyzeFinding(finding models.Finding, retentionYears int) *HNDLAnalysis {
	config := DefaultHNDLConfig()

	// Set vulnerability factor based on quantum threat level
	switch finding.QuantumThreat {
	case models.ThreatBrokenByShor:
		config.VulnerabilityFactor = 1.0
	case models.ThreatWeakenedByGrover:
		config.VulnerabilityFactor = 0.3
	case models.ThreatNotDirectlyThreatened:
		config.VulnerabilityFactor = 0.0
	}

	// Set data value factor based on algorithm category
	switch finding.Category {
	case models.CategoryAsymmetricEncryption, models.CategoryKeyExchange:
		config.DataValueFactor = 0.9
	case models.CategoryDigitalSignature, models.CategoryCertificate:
		config.DataValueFactor = 0.7
	case models.CategorySymmetricEncryption:
		config.DataValueFactor = 0.6
	default:
		config.DataValueFactor = 0.5
	}

	// Adjust harvest probability based on severity
	switch finding.Severity {
	case models.SeverityCritical:
		config.HarvestProbability = 0.25
	case models.SeverityHigh:
		config.HarvestProbability = 0.20
	case models.SeverityMedium:
		config.HarvestProbability = 0.15
	case models.SeverityLow:
		config.HarvestProbability = 0.10
	}

	if retentionYears > 0 {
		config.DataRetentionYears = retentionYears
	}

	// Adjust analysis window based on retention
	config.AnalysisEndYear = config.AnalysisStartYear + config.DataRetentionYears + 5

	// Short retention reduces overall risk: if data expires before quantum is
	// available, the attack lifecycle terminates early
	if retentionYears > 0 && retentionYears < 5 {
		config.DataValueFactor *= float64(retentionYears) / 5.0
	}

	analyzer := NewHNDLAnalyzer(config)
	return analyzer.Analyze()
}
