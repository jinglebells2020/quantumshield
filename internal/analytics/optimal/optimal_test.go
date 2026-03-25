package optimal

import (
	"fmt"
	"testing"
	"time"

	"quantumshield/pkg/models"
)

func makeShorFindings(n int) []models.Finding {
	findings := make([]models.Finding, n)
	for i := range findings {
		findings[i] = models.Finding{
			ID:            fmt.Sprintf("F-%d", i),
			Severity:      models.SeverityCritical,
			QuantumThreat: models.ThreatBrokenByShor,
			Category:      models.CategoryAsymmetricEncryption,
			Algorithm:     "RSA-2048",
			Confidence:    0.95,
		}
	}
	return findings
}

func makeMixedFindings(n int) []models.Finding {
	findings := make([]models.Finding, n)
	for i := range findings {
		threat := models.ThreatBrokenByShor
		if i%3 == 1 {
			threat = models.ThreatWeakenedByGrover
		} else if i%3 == 2 {
			threat = models.ThreatNotDirectlyThreatened
		}
		findings[i] = models.Finding{
			ID:            fmt.Sprintf("F-%d", i),
			Severity:      models.Severity(i % 4),
			QuantumThreat: threat,
			Category:      models.AlgorithmCategory(i % 5),
			Algorithm:     "RSA-2048",
			Confidence:    0.9,
		}
	}
	return findings
}

// TestOptimalTiming_UrgentDeadline verifies that when the deadline is only
// about 2 months away, there is only one quarter evaluated and the optimizer
// must pick it (start now).
func TestOptimalTiming_UrgentDeadline(t *testing.T) {
	deadline := time.Now().Add(2 * 30 * 24 * time.Hour) // ~2 months, < 1 quarter
	opt := NewMigrationTimingOptimizer(deadline)

	rec, err := opt.ComputeOptimalTiming(TimingParams{
		CurrentFindings:      makeShorFindings(10),
		BaseMigrationCostUSD: 200000,
		DataBreachCostUSD:    50000000, // high breach cost forces urgency
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With such a tight deadline only one quarter (now) should be evaluated
	if len(rec.CostCurve) != 1 {
		t.Fatalf("expected exactly 1 cost curve entry for ~2-month deadline, got %d", len(rec.CostCurve))
	}
	firstDate := rec.CostCurve[0].Date
	if !rec.OptimalStartDate.Equal(firstDate) {
		t.Errorf("expected optimal start = first quarter (%v), got %v", firstDate, rec.OptimalStartDate)
	}
}

// TestOptimalTiming_DistantDeadline verifies that with a 10-year horizon the
// optimizer does not necessarily pick the first quarter.
func TestOptimalTiming_DistantDeadline(t *testing.T) {
	deadline := time.Now().AddDate(10, 0, 0)
	opt := NewMigrationTimingOptimizer(deadline)

	rec, err := opt.ComputeOptimalTiming(TimingParams{
		CurrentFindings:      makeMixedFindings(20),
		BaseMigrationCostUSD: 500000,
		DataBreachCostUSD:    5000000,
		ToolImprovementRate:  0.2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the recommendation has a valid quarter label
	if rec.OptimalStartQuarter == "" {
		t.Error("optimal start quarter should not be empty")
	}

	// With distant deadline, the cost curve should have many entries
	if len(rec.CostCurve) < 10 {
		t.Errorf("expected at least 10 cost curve entries, got %d", len(rec.CostCurve))
	}

	// The optimal cost must be <= every point on the curve
	for _, pt := range rec.CostCurve {
		if pt.TotalExpectedCost < rec.ExpectedTotalCost-1e-6 {
			t.Errorf("found curve point (%v) with lower cost %.2f than optimal %.2f",
				pt.Date, pt.TotalExpectedCost, rec.ExpectedTotalCost)
		}
	}
}

// TestOptimalTiming_HighBreachCost verifies that a very high breach cost
// pushes the optimal start earlier compared to a lower breach cost.
func TestOptimalTiming_HighBreachCost(t *testing.T) {
	deadline := time.Now().AddDate(8, 0, 0)
	findings := makeShorFindings(15)

	optLow := NewMigrationTimingOptimizer(deadline)
	recLow, err := optLow.ComputeOptimalTiming(TimingParams{
		CurrentFindings:      findings,
		BaseMigrationCostUSD: 300000,
		DataBreachCostUSD:    1000000,
	})
	if err != nil {
		t.Fatalf("unexpected error (low breach): %v", err)
	}

	optHigh := NewMigrationTimingOptimizer(deadline)
	recHigh, err := optHigh.ComputeOptimalTiming(TimingParams{
		CurrentFindings:      findings,
		BaseMigrationCostUSD: 300000,
		DataBreachCostUSD:    100000000, // $100M
	})
	if err != nil {
		t.Fatalf("unexpected error (high breach): %v", err)
	}

	// High breach cost should lead to an equal or earlier optimal start
	if recHigh.OptimalStartDate.After(recLow.OptimalStartDate) {
		t.Errorf("high breach cost optimal date (%v) should be <= low breach cost optimal date (%v)",
			recHigh.OptimalStartDate, recLow.OptimalStartDate)
	}
}

// TestOptimalTiming_CostCurveExists verifies that the cost curve is populated.
func TestOptimalTiming_CostCurveExists(t *testing.T) {
	deadline := time.Now().AddDate(3, 0, 0)
	opt := NewMigrationTimingOptimizer(deadline)

	rec, err := opt.ComputeOptimalTiming(TimingParams{
		CurrentFindings: makeMixedFindings(5),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rec.CostCurve) == 0 {
		t.Fatal("cost curve should not be empty")
	}

	for i, pt := range rec.CostCurve {
		if pt.TotalExpectedCost <= 0 {
			t.Errorf("curve[%d] total cost should be positive, got %f", i, pt.TotalExpectedCost)
		}
		if pt.MigrationCost < 0 {
			t.Errorf("curve[%d] migration cost should be non-negative, got %f", i, pt.MigrationCost)
		}
	}

	// Confidence should be reasonable
	if rec.Confidence <= 0 || rec.Confidence > 1 {
		t.Errorf("confidence should be in (0,1], got %f", rec.Confidence)
	}
}

// TestOptimalTiming_NoFindings verifies that an error is returned when there
// are no findings.
func TestOptimalTiming_NoFindings(t *testing.T) {
	deadline := time.Now().AddDate(5, 0, 0)
	opt := NewMigrationTimingOptimizer(deadline)

	_, err := opt.ComputeOptimalTiming(TimingParams{
		CurrentFindings: nil,
	})
	if err == nil {
		t.Error("expected error for empty findings, got nil")
	}

	_, err = opt.ComputeOptimalTiming(TimingParams{
		CurrentFindings: []models.Finding{},
	})
	if err == nil {
		t.Error("expected error for empty findings slice, got nil")
	}
}
