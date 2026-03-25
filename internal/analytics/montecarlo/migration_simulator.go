package montecarlo

import (
	"math"
	"sort"
	"time"

	"quantumshield/pkg/models"
)

// MigrationSimConfig holds all parameters for a Monte Carlo migration simulation.
type MigrationSimConfig struct {
	// Findings to simulate migration for.
	Findings []models.Finding

	// NumSimulations is the number of Monte Carlo iterations. Default 10000.
	NumSimulations int

	// ScanIntervalDays is how often scans run (sprint length proxy). Default 7.
	ScanIntervalDays int

	// ComplianceDeadline is the hard deadline; if zero, no deadline probability is computed.
	ComplianceDeadline time.Time

	// HourlyRate is the cost per engineering hour. Default 150.
	HourlyRate float64

	// AutoFixMean is the mean hours for an auto-fixable finding (log-scale mu). Default 0.5.
	AutoFixMean float64

	// AutoFixStd is the std-dev for auto-fixable findings (log-scale sigma). Default 0.3.
	AutoFixStd float64

	// ManualFixMean is the mean hours for a manual fix (log-scale mu). Default 4.0.
	ManualFixMean float64

	// ManualFixStd is the std-dev for manual fixes (log-scale sigma). Default 2.0.
	ManualFixStd float64

	// DepUpdateMeanDays is the mean wait time (days) for a dependency update. Default 30.
	DepUpdateMeanDays float64

	// RegressionProb is the probability a sprint introduces a regression. Default 0.05.
	RegressionProb float64

	// RegressionFixMean is the mean hours to fix a regression (log-scale mu). Default 2.0.
	RegressionFixMean float64
}

// applyDefaults fills in zero-valued config fields with their defaults.
func (c *MigrationSimConfig) applyDefaults() {
	if c.NumSimulations <= 0 {
		c.NumSimulations = 10000
	}
	if c.ScanIntervalDays <= 0 {
		c.ScanIntervalDays = 7
	}
	if c.HourlyRate <= 0 {
		c.HourlyRate = 150
	}
	if c.AutoFixMean <= 0 {
		c.AutoFixMean = 0.5
	}
	if c.AutoFixStd <= 0 {
		c.AutoFixStd = 0.3
	}
	if c.ManualFixMean <= 0 {
		c.ManualFixMean = 4.0
	}
	if c.ManualFixStd <= 0 {
		c.ManualFixStd = 2.0
	}
	if c.DepUpdateMeanDays <= 0 {
		c.DepUpdateMeanDays = 30
	}
	if c.RegressionProb < 0 {
		c.RegressionProb = 0.05
	}
	if c.RegressionFixMean <= 0 {
		c.RegressionFixMean = 2.0
	}
}

// SimulationResult holds the full output of a Monte Carlo migration simulation.
type SimulationResult struct {
	// Summary statistics for completion time in weeks.
	MeanWeeks   float64
	MedianWeeks float64
	P10Weeks    float64
	P90Weeks    float64

	// Summary statistics for total cost.
	MeanCost   float64
	MedianCost float64
	P10Cost    float64
	P90Cost    float64

	// WeeklyCompletionCDF maps week number to cumulative probability of completion.
	WeeklyCompletionCDF map[int]float64

	// DeadlineProbability is the probability of finishing before ComplianceDeadline (0 if no deadline).
	DeadlineProbability float64

	// TotalRegressions is the mean number of regressions across simulations.
	TotalRegressions float64

	// DepBlocks is the mean number of dependency-blocked findings across simulations.
	DepBlocks float64

	// FindingRiskRanking ranks findings by their variance contribution to total time.
	FindingRiskRanking []FindingSimRisk

	// RawWeeks contains the raw distribution of completion times (one per simulation).
	RawWeeks []float64

	// RawCosts contains the raw distribution of costs (one per simulation).
	RawCosts []float64
}

// FindingSimRisk represents a single finding's contribution to simulation variance.
type FindingSimRisk struct {
	FindingID          string
	Algorithm          string
	Severity           string
	MeanHours          float64
	StdHours           float64
	VarianceContrib    float64 // fraction of total variance attributable to this finding
	IsDepBlocked       bool
	IsAutoFixable      bool
}

// SensitivityResult holds the output of a sensitivity analysis.
type SensitivityResult struct {
	Parameters []ParameterSensitivity
}

// ParameterSensitivity captures how a single parameter affects the simulation outcome.
type ParameterSensitivity struct {
	Name             string
	BaselineValue    float64
	LowValue         float64
	HighValue        float64
	MeanAtLow        float64
	MeanAtHigh       float64
	SensitivityIndex float64 // |high - low| / baseline_mean
}

// Simulate runs the full Monte Carlo simulation and returns aggregated results.
func (c *MigrationSimConfig) Simulate() *SimulationResult {
	c.applyDefaults()

	sim := NewMigrationSimulator(42)
	numFindings := len(c.Findings)

	weeksDist := make([]float64, c.NumSimulations)
	costsDist := make([]float64, c.NumSimulations)

	// Track per-finding hours across simulations for variance analysis.
	findingHours := make([][]float64, numFindings)
	for i := range findingHours {
		findingHours[i] = make([]float64, c.NumSimulations)
	}

	totalRegressions := 0.0
	totalDepBlocks := 0.0

	parallelism := math.Max(1, math.Ceil(float64(numFindings)/10.0))

	for s := 0; s < c.NumSimulations; s++ {
		var totalHours float64
		var maxDepWaitDays float64
		depBlockCount := 0

		for i, f := range c.Findings {
			var hours float64

			if f.InDependency {
				// Dependency-blocked: exponential wait for update, then fix.
				depWaitDays := sim.SampleExponential(c.DepUpdateMeanDays)
				if depWaitDays > maxDepWaitDays {
					maxDepWaitDays = depWaitDays
				}
				depBlockCount++
				// Still need some fix time after the dep updates.
				hours = sim.SampleLogNormal(c.AutoFixMean, c.AutoFixStd)
			} else if f.AutoFixAvailable {
				hours = sim.SampleLogNormal(c.AutoFixMean, c.AutoFixStd)
			} else {
				hours = sim.SampleLogNormal(c.ManualFixMean, c.ManualFixStd)
			}

			findingHours[i][s] = hours
			totalHours += hours
		}

		// Wall-clock hours accounting for parallelism.
		wallClockHours := totalHours / parallelism

		// Convert dep wait from days to hours and add if it exceeds parallel work time.
		depWaitHours := maxDepWaitDays * 8 // 8-hour work days
		if depWaitHours > wallClockHours {
			wallClockHours = depWaitHours
		}

		// Simulate regressions per sprint.
		wallClockWeeks := wallClockHours / 40.0
		numSprints := math.Ceil(wallClockWeeks / (float64(c.ScanIntervalDays) / 7.0))
		regressionCount := 0
		for sp := 0; sp < int(numSprints); sp++ {
			if sim.SampleBernoulli(c.RegressionProb) {
				regressionCount++
				regrHours := sim.SampleLogNormal(c.RegressionFixMean, 1.0)
				wallClockHours += regrHours
			}
		}

		totalRegressions += float64(regressionCount)
		totalDepBlocks += float64(depBlockCount)

		// Recompute weeks after regressions.
		wallClockWeeks = wallClockHours / 40.0
		weeksDist[s] = wallClockWeeks
		costsDist[s] = totalHours * c.HourlyRate
	}

	// Sort distributions for percentile computation.
	sortedWeeks := make([]float64, c.NumSimulations)
	copy(sortedWeeks, weeksDist)
	SortFloat64s(sortedWeeks)

	sortedCosts := make([]float64, c.NumSimulations)
	copy(sortedCosts, costsDist)
	SortFloat64s(sortedCosts)

	// Compute summary statistics.
	result := &SimulationResult{
		MeanWeeks:   mean(weeksDist),
		MedianWeeks: Percentile(sortedWeeks, 50),
		P10Weeks:    Percentile(sortedWeeks, 10),
		P90Weeks:    Percentile(sortedWeeks, 90),
		MeanCost:    mean(costsDist),
		MedianCost:  Percentile(sortedCosts, 50),
		P10Cost:     Percentile(sortedCosts, 10),
		P90Cost:     Percentile(sortedCosts, 90),

		TotalRegressions: totalRegressions / float64(c.NumSimulations),
		DepBlocks:        totalDepBlocks / float64(c.NumSimulations),

		RawWeeks: weeksDist,
		RawCosts: costsDist,
	}

	// Build weekly completion CDF.
	maxWeek := int(math.Ceil(sortedWeeks[len(sortedWeeks)-1]))
	if maxWeek < 1 {
		maxWeek = 1
	}
	result.WeeklyCompletionCDF = make(map[int]float64, maxWeek)
	for w := 1; w <= maxWeek; w++ {
		count := 0
		for _, wk := range weeksDist {
			if wk <= float64(w) {
				count++
			}
		}
		result.WeeklyCompletionCDF[w] = float64(count) / float64(c.NumSimulations)
	}

	// Deadline probability.
	if !c.ComplianceDeadline.IsZero() {
		deadlineWeeks := c.ComplianceDeadline.Sub(time.Now()).Hours() / (40 * 7 / 5)
		// Convert to work-weeks: hours / 40
		deadlineWorkWeeks := c.ComplianceDeadline.Sub(time.Now()).Hours() / 168.0 // calendar weeks
		count := 0
		for _, wk := range weeksDist {
			if wk <= deadlineWorkWeeks {
				count++
			}
		}
		_ = deadlineWeeks
		result.DeadlineProbability = float64(count) / float64(c.NumSimulations)
	}

	// Finding risk ranking by variance contribution.
	result.FindingRiskRanking = computeRiskRanking(c.Findings, findingHours, c.NumSimulations)

	return result
}

// computeRiskRanking ranks findings by their variance contribution.
func computeRiskRanking(findings []models.Finding, findingHours [][]float64, numSims int) []FindingSimRisk {
	risks := make([]FindingSimRisk, len(findings))
	totalVariance := 0.0

	for i, f := range findings {
		m := mean(findingHours[i])
		v := variance(findingHours[i], m)
		totalVariance += v

		risks[i] = FindingSimRisk{
			FindingID:     f.ID,
			Algorithm:     f.Algorithm,
			Severity:      f.Severity.String(),
			MeanHours:     m,
			StdHours:      math.Sqrt(v),
			IsDepBlocked:  f.InDependency,
			IsAutoFixable: f.AutoFixAvailable,
		}
	}

	// Assign variance contribution fractions.
	if totalVariance > 0 {
		for i := range risks {
			v := variance(findingHours[i], risks[i].MeanHours)
			risks[i].VarianceContrib = v / totalVariance
		}
	}

	// Sort by variance contribution descending.
	sort.Slice(risks, func(a, b int) bool {
		return risks[a].VarianceContrib > risks[b].VarianceContrib
	})

	return risks
}

// SensitivityAnalysis varies key parameters +/-20% and measures impact on mean completion time.
func (c *MigrationSimConfig) SensitivityAnalysis() *SensitivityResult {
	c.applyDefaults()

	// Get baseline.
	baseResult := c.Simulate()
	baselineMean := baseResult.MeanWeeks

	type paramDef struct {
		name     string
		getVal   func() float64
		setVal   func(float64)
		resetVal func()
	}

	origAutoFix := c.AutoFixMean
	origManualFix := c.ManualFixMean
	origDepUpdate := c.DepUpdateMeanDays
	origRegProb := c.RegressionProb

	params := []paramDef{
		{
			name:     "AutoFixMean",
			getVal:   func() float64 { return origAutoFix },
			setVal:   func(v float64) { c.AutoFixMean = v },
			resetVal: func() { c.AutoFixMean = origAutoFix },
		},
		{
			name:     "ManualFixMean",
			getVal:   func() float64 { return origManualFix },
			setVal:   func(v float64) { c.ManualFixMean = v },
			resetVal: func() { c.ManualFixMean = origManualFix },
		},
		{
			name:     "DepUpdateMeanDays",
			getVal:   func() float64 { return origDepUpdate },
			setVal:   func(v float64) { c.DepUpdateMeanDays = v },
			resetVal: func() { c.DepUpdateMeanDays = origDepUpdate },
		},
		{
			name:     "RegressionProb",
			getVal:   func() float64 { return origRegProb },
			setVal:   func(v float64) { c.RegressionProb = v },
			resetVal: func() { c.RegressionProb = origRegProb },
		},
	}

	result := &SensitivityResult{
		Parameters: make([]ParameterSensitivity, len(params)),
	}

	for i, p := range params {
		baseVal := p.getVal()
		lowVal := baseVal * 0.8
		highVal := baseVal * 1.2

		// Run at low value.
		p.setVal(lowVal)
		lowResult := c.Simulate()
		meanAtLow := lowResult.MeanWeeks
		p.resetVal()

		// Run at high value.
		p.setVal(highVal)
		highResult := c.Simulate()
		meanAtHigh := highResult.MeanWeeks
		p.resetVal()

		sensIndex := 0.0
		if baselineMean > 0 {
			sensIndex = math.Abs(meanAtHigh-meanAtLow) / baselineMean
		}

		result.Parameters[i] = ParameterSensitivity{
			Name:             p.name,
			BaselineValue:    baseVal,
			LowValue:         lowVal,
			HighValue:        highVal,
			MeanAtLow:        meanAtLow,
			MeanAtHigh:       meanAtHigh,
			SensitivityIndex: sensIndex,
		}
	}

	// Sort by sensitivity index descending.
	sort.Slice(result.Parameters, func(a, b int) bool {
		return result.Parameters[a].SensitivityIndex > result.Parameters[b].SensitivityIndex
	})

	return result
}

// mean computes the arithmetic mean of a slice.
func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// variance computes the population variance given a precomputed mean.
func variance(vals []float64, m float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sumSq := 0.0
	for _, v := range vals {
		d := v - m
		sumSq += d * d
	}
	return sumSq / float64(len(vals))
}
