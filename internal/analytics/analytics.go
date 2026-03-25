// Package analytics orchestrates all QuantumShield analytics modules.
package analytics

import (
	"context"
	"log"
	"sync"
	"time"

	"quantumshield/internal/analytics/bayesian"
	"quantumshield/internal/analytics/fourier"
	"quantumshield/internal/analytics/hmm"
	"quantumshield/internal/analytics/markov"
	"quantumshield/internal/analytics/montecarlo"
	"quantumshield/internal/analytics/optimal"
	"quantumshield/internal/analytics/spectral"
	"quantumshield/internal/analytics/tda"
	"quantumshield/pkg/models"
)

// FullAnalysis contains the combined output of all analytics modules.
type FullAnalysis struct {
	RiskScore             float64                              `json:"risk_score"`
	QuantumReadiness      float64                              `json:"quantum_readiness"`
	AdjustedFindings      []bayesian.BayesianAssessment        `json:"adjusted_findings"`
	FalsePositiveRate     float64                              `json:"estimated_false_positive_rate"`
	MigrationPrediction   *markov.MigrationPrediction          `json:"migration_prediction,omitempty"`
	DeveloperProfiles     []*markov.DeveloperProfile           `json:"developer_profiles,omitempty"`
	HNDLAssessments       []*markov.HNDLAnalysis               `json:"hndl_assessments,omitempty"`
	MigrationSimulation   *montecarlo.SimulationResult         `json:"migration_simulation,omitempty"`
	MigrationPhases       *spectral.PartitionResult            `json:"migration_phases,omitempty"`
	OptimalTiming         *optimal.TimingRecommendation        `json:"optimal_timing,omitempty"`
	VulnPatterns          []hmm.VulnerabilityPattern           `json:"vulnerability_patterns,omitempty"`
	TopologicalAnalysis   *tda.PersistenceResult               `json:"topological_analysis,omitempty"`
	EntropyAnomalies      []fourier.EntropyAnomaly             `json:"entropy_anomalies,omitempty"`
	TrafficClassification []fourier.CipherSuiteClassification  `json:"traffic_classification,omitempty"`
	AnalysisVersion       string                               `json:"analysis_version"`
	ComputedAt            time.Time                            `json:"computed_at"`
	DurationMs            int64                                `json:"duration_ms"`
}

// AnalysisConfig controls which modules to run.
type AnalysisConfig struct {
	RunBayesian          bool      `json:"run_bayesian"`
	RunMarkov            bool      `json:"run_markov"`
	RunHNDL              bool      `json:"run_hndl"`
	RunMonteCarlo        bool      `json:"run_monte_carlo"`
	RunSpectral          bool      `json:"run_spectral"`
	RunOptimalTiming     bool      `json:"run_optimal_timing"`
	RunHMM               bool      `json:"run_hmm"`
	RunTDA               bool      `json:"run_tda"`
	RunEntropy           bool      `json:"run_entropy"`
	RunTrafficAnalysis   bool      `json:"run_traffic_analysis"`
	MonteCarloIterations int       `json:"monte_carlo_iterations"`
	ComplianceDeadline   time.Time `json:"compliance_deadline"`
	DataBreachCostUSD    float64   `json:"data_breach_cost_usd"`
	HourlyDevRate        float64   `json:"hourly_dev_rate"`
}

// DefaultConfig returns a config with all modules enabled and sensible defaults.
func DefaultConfig() AnalysisConfig {
	return AnalysisConfig{
		RunBayesian:          true,
		RunMarkov:            true,
		RunHNDL:              true,
		RunMonteCarlo:        true,
		RunSpectral:          true,
		RunOptimalTiming:     true,
		RunHMM:               true,
		RunTDA:               true,
		RunEntropy:           true,
		RunTrafficAnalysis:   true,
		MonteCarloIterations: 10000,
		ComplianceDeadline:   time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		DataBreachCostUSD:    5000000,
		HourlyDevRate:        150,
	}
}

// AnalysisInput contains all optional inputs for the analysis pipeline.
type AnalysisInput struct {
	CurrentScan         models.ScanResult
	ScanHistory         *models.ScanHistory
	CommitHistory       []models.CryptoCommit
	DependencyGraph     *models.DependencyGraph
	NetworkCaptures     []models.TLSHandshake
	SourceDirectory     string
	CryptoOutputSamples map[string][]byte
}

// Analyzer orchestrates all analytics modules.
type Analyzer struct {
	config AnalysisConfig
}

// NewAnalyzer creates an analyzer with the given configuration.
func NewAnalyzer(config AnalysisConfig) *Analyzer {
	return &Analyzer{config: config}
}

// Analyze runs the full analytics pipeline concurrently.
func (a *Analyzer) Analyze(ctx context.Context, input AnalysisInput) (*FullAnalysis, error) {
	start := time.Now()
	result := &FullAnalysis{
		RiskScore:        input.CurrentScan.Summary.RiskScore,
		QuantumReadiness: input.CurrentScan.Summary.QuantumReadiness,
		AnalysisVersion:  "1.0.0",
		ComputedAt:       start,
	}

	findings := input.CurrentScan.Findings

	// Phase 1: Bayesian FP reduction
	if a.config.RunBayesian && len(findings) > 0 {
		fpr := bayesian.NewFalsePositiveReducer()
		assessments := fpr.AssessAll(findings)
		result.AdjustedFindings = assessments
		fpCount := 0
		for _, as := range assessments {
			if !as.IsTruePositive {
				fpCount++
			}
		}
		if len(assessments) > 0 {
			result.FalsePositiveRate = float64(fpCount) / float64(len(assessments))
		}
	}

	// Phase 2: Run independent modules concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Markov migration prediction
	if a.config.RunMarkov && input.ScanHistory != nil && len(input.ScanHistory.Scans) >= 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mp := markov.NewMigrationPredictor()
			pred, err := mp.Predict(input.ScanHistory)
			if err != nil {
				log.Printf("markov: %v", err)
				return
			}
			mu.Lock()
			result.MigrationPrediction = pred
			mu.Unlock()
		}()
	}

	// Developer profiles
	if a.config.RunMarkov && len(input.CommitHistory) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dm := markov.NewDeveloperModeler()
			profiles := dm.BuildAllProfiles(input.CommitHistory)
			mu.Lock()
			result.DeveloperProfiles = profiles
			mu.Unlock()
		}()
	}

	// HNDL analysis
	if a.config.RunHNDL && len(findings) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var assessments []*markov.HNDLAnalysis
			for _, f := range findings {
				if f.QuantumThreat == models.ThreatBrokenByShor {
					analysis := markov.AnalyzeFinding(f, 10)
					if analysis != nil {
						assessments = append(assessments, analysis)
					}
				}
			}
			mu.Lock()
			result.HNDLAssessments = assessments
			mu.Unlock()
		}()
	}

	// Monte Carlo simulation
	if a.config.RunMonteCarlo && len(findings) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			simCfg := &montecarlo.MigrationSimConfig{
				Findings:           findings,
				NumSimulations:     a.config.MonteCarloIterations,
				ComplianceDeadline: a.config.ComplianceDeadline,
				HourlyRate:         a.config.HourlyDevRate,
			}
			sim := simCfg.Simulate()
			mu.Lock()
			result.MigrationSimulation = sim
			mu.Unlock()
		}()
	}

	// Spectral partitioning
	if a.config.RunSpectral && input.DependencyGraph != nil && len(input.DependencyGraph.Nodes) > 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dp := spectral.NewDependencyPartitioner()
			partition, err := dp.Partition(input.DependencyGraph)
			if err != nil {
				log.Printf("spectral: %v", err)
				return
			}
			mu.Lock()
			result.MigrationPhases = partition
			mu.Unlock()
		}()
	}

	// Optimal timing
	if a.config.RunOptimalTiming && len(findings) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mto := optimal.NewMigrationTimingOptimizer(a.config.ComplianceDeadline)
			rec, err := mto.ComputeOptimalTiming(optimal.TimingParams{
				CurrentFindings:      findings,
				BaseMigrationCostUSD: 100000,
				DataBreachCostUSD:    a.config.DataBreachCostUSD,
				NumDevelopers:        2,
				HourlyRate:           a.config.HourlyDevRate,
			})
			if err != nil {
				log.Printf("optimal: %v", err)
				return
			}
			mu.Lock()
			result.OptimalTiming = rec
			mu.Unlock()
		}()
	}

	// TDA persistence
	if a.config.RunTDA && len(findings) > 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pa := tda.NewPersistenceAnalyzer()
			pr, err := pa.ComputePersistence(findings)
			if err != nil {
				log.Printf("tda: %v", err)
				return
			}
			mu.Lock()
			result.TopologicalAnalysis = pr
			mu.Unlock()
		}()
	}

	// Entropy analysis
	if a.config.RunEntropy && input.SourceDirectory != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ea := fourier.NewEntropyAnalyzer()
			profiles, err := ea.ScanDirectory(input.SourceDirectory)
			if err != nil {
				log.Printf("entropy: %v", err)
				return
			}
			var anomalies []fourier.EntropyAnomaly
			for _, p := range profiles {
				anomalies = append(anomalies, p.Anomalies...)
			}
			mu.Lock()
			result.EntropyAnomalies = anomalies
			mu.Unlock()
		}()
	}

	// Traffic analysis
	if a.config.RunTrafficAnalysis && len(input.NetworkCaptures) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tf := fourier.NewTrafficFingerprinter()
			classifications := tf.DetectQuantumVulnerableSuites(input.NetworkCaptures)
			mu.Lock()
			result.TrafficClassification = classifications
			mu.Unlock()
		}()
	}

	wg.Wait()
	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}
