package optimal

import (
	"fmt"
	"math"
	"time"

	"quantumshield/pkg/models"
)

// TimingRecommendation is the output of optimal stopping analysis.
type TimingRecommendation struct {
	OptimalStartQuarter string             `json:"optimal_start_quarter"`
	OptimalStartDate    time.Time          `json:"optimal_start_date"`
	ExpectedTotalCost   float64            `json:"expected_total_cost_usd"`
	CostBreakdown       CostBreakdown      `json:"cost_breakdown"`
	RiskIfDelayed       map[string]float64 `json:"risk_if_delayed"`
	CostCurve           []TimeCostPoint    `json:"cost_curve"`
	Confidence          float64            `json:"confidence"`
	Rationale           string             `json:"rationale"`
}

type CostBreakdown struct {
	MigrationCost    float64 `json:"migration_cost"`
	RiskExposureCost float64 `json:"risk_exposure_cost"`
	OpportunityCost  float64 `json:"opportunity_cost"`
}

type TimeCostPoint struct {
	Date              time.Time `json:"date"`
	MigrationCost     float64   `json:"migration_cost"`
	RiskCost          float64   `json:"risk_cost"`
	TotalExpectedCost float64   `json:"total_expected_cost"`
}

type TimingOption func(*MigrationTimingOptimizer)

func WithCRQCMidpoint(year float64) TimingOption {
	return func(m *MigrationTimingOptimizer) { m.crqcMidpointYear = year }
}

type TimingParams struct {
	CurrentFindings      []models.Finding
	BaseMigrationCostUSD float64
	DataBreachCostUSD    float64
	ToolImprovementRate  float64
	NumDevelopers        int
	HourlyRate           float64
}

// MigrationTimingOptimizer finds optimal migration start date.
type MigrationTimingOptimizer struct {
	complianceDeadline time.Time
	crqcMidpointYear   float64
	crqcSteepness      float64
}

// NewMigrationTimingOptimizer creates an optimizer.
func NewMigrationTimingOptimizer(deadline time.Time, opts ...TimingOption) *MigrationTimingOptimizer {
	m := &MigrationTimingOptimizer{
		complianceDeadline: deadline,
		crqcMidpointYear:   2032,
		crqcSteepness:      0.5,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// ComputeOptimalTiming evaluates total cost per quarter and returns the minimum.
// C_total(t) = C_migration(t) + C_risk(t) + C_opportunity(t)
// C_migration decreases as tools improve. C_risk increases as quantum approaches.
func (mto *MigrationTimingOptimizer) ComputeOptimalTiming(params TimingParams) (*TimingRecommendation, error) {
	if len(params.CurrentFindings) == 0 {
		return nil, fmt.Errorf("no findings to analyze")
	}
	if params.BaseMigrationCostUSD <= 0 {
		params.BaseMigrationCostUSD = 100000
	}
	if params.DataBreachCostUSD <= 0 {
		params.DataBreachCostUSD = 5000000
	}
	if params.ToolImprovementRate <= 0 {
		params.ToolImprovementRate = 0.15
	}
	if params.NumDevelopers <= 0 {
		params.NumDevelopers = 2
	}
	if params.HourlyRate <= 0 {
		params.HourlyRate = 150
	}

	now := time.Now()
	deadline := mto.complianceDeadline
	if deadline.Before(now) {
		deadline = now.AddDate(5, 0, 0)
	}

	// Count Shor-vulnerable findings for risk weighting
	shorCount := 0
	for _, f := range params.CurrentFindings {
		if f.QuantumThreat == models.ThreatBrokenByShor {
			shorCount++
		}
	}
	vulnFraction := float64(shorCount) / float64(len(params.CurrentFindings))
	if vulnFraction == 0 {
		vulnFraction = 0.1
	}

	var curve []TimeCostPoint
	bestCost := math.Inf(1)
	var bestDate time.Time
	var bestBreakdown CostBreakdown

	// Evaluate each quarter from now to deadline
	for t := now; t.Before(deadline); t = t.AddDate(0, 3, 0) {
		yearsFromNow := t.Sub(now).Hours() / 8766

		// Migration cost: decreases as tools improve
		decay := 1.0 / (1.0 + params.ToolImprovementRate*yearsFromNow)
		migCost := params.BaseMigrationCostUSD * decay

		// Risk cost: sum of expected exploit costs from now until migration completes
		// Using HNDL logistic model for quantum availability
		riskCost := 0.0
		for yr := float64(now.Year()); yr <= float64(t.Year()); yr++ {
			pQuantum := 1.0 / (1.0 + math.Exp(-mto.crqcSteepness*(yr-mto.crqcMidpointYear)))
			pExploit := pQuantum * vulnFraction * 0.15 // harvest rate * quantum * vuln fraction
			discountYears := yr - float64(now.Year())
			discount := math.Pow(0.95, discountYears)
			riskCost += pExploit * params.DataBreachCostUSD * discount
		}

		// Opportunity cost: urgency premium if close to deadline
		yearsToDeadline := deadline.Sub(t).Hours() / 8766
		urgencyPremium := 0.0
		if yearsToDeadline < 1 {
			urgencyPremium = 0.5
		}
		migHours := float64(len(params.CurrentFindings)) * 4 // rough estimate
		oppCost := float64(params.NumDevelopers) * params.HourlyRate * migHours * (1 + urgencyPremium) * 0.1

		totalCost := migCost + riskCost + oppCost

		curve = append(curve, TimeCostPoint{
			Date:              t,
			MigrationCost:     migCost,
			RiskCost:          riskCost,
			TotalExpectedCost: totalCost,
		})

		if totalCost < bestCost {
			bestCost = totalCost
			bestDate = t
			bestBreakdown = CostBreakdown{
				MigrationCost:    migCost,
				RiskExposureCost: riskCost,
				OpportunityCost:  oppCost,
			}
		}
	}

	// Compute risk if delayed
	riskIfDelayed := make(map[string]float64)
	for _, pt := range curve {
		if pt.Date.After(bestDate) {
			q := quarterLabel(pt.Date)
			increase := (pt.TotalExpectedCost - bestCost) / bestCost * 100
			riskIfDelayed[q] = increase
		}
	}

	rec := &TimingRecommendation{
		OptimalStartQuarter: quarterLabel(bestDate),
		OptimalStartDate:    bestDate,
		ExpectedTotalCost:   bestCost,
		CostBreakdown:       bestBreakdown,
		RiskIfDelayed:       riskIfDelayed,
		CostCurve:           curve,
		Confidence:          0.7,
		Rationale:           fmt.Sprintf("Optimal start minimizes combined migration cost ($%.0f) and quantum risk exposure ($%.0f)", bestBreakdown.MigrationCost, bestBreakdown.RiskExposureCost),
	}

	return rec, nil
}

func quarterLabel(t time.Time) string {
	q := (t.Month()-1)/3 + 1
	return fmt.Sprintf("Q%d %d", q, t.Year())
}
