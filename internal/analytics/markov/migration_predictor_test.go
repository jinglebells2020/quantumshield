package markov

import (
	"math"
	"testing"
	"time"

	"quantumshield/pkg/models"
)

func TestClassifyState(t *testing.T) {
	tests := []struct {
		name     string
		qr       float64
		expected MigrationState
	}{
		{"zero", 0, FullyVuln},
		{"just_below_10", 9.99, FullyVuln},
		{"exactly_10", 10, MostlyVuln},
		{"just_below_40", 39.99, MostlyVuln},
		{"exactly_40", 40, PartiallyVuln},
		{"just_below_70", 69.99, PartiallyVuln},
		{"exactly_70", 70, MostlySafe},
		{"just_below_95", 94.99, MostlySafe},
		{"exactly_95", 95, QuantumSafe},
		{"max_100", 100, QuantumSafe},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyState(tt.qr)
			if got != tt.expected {
				t.Errorf("ClassifyState(%f) = %v, want %v", tt.qr, got, tt.expected)
			}
		})
	}
}

func makeScanHistory(readinessScores []float64, baseTime time.Time, intervalDays int) *models.ScanHistory {
	scans := make([]models.ScanResult, len(readinessScores))
	for i, qr := range readinessScores {
		scans[i] = models.ScanResult{
			StartedAt: baseTime.Add(time.Duration(i*intervalDays*24) * time.Hour),
			Summary: models.ScanSummary{
				QuantumReadiness: qr,
			},
		}
	}
	return &models.ScanHistory{
		ProjectID: "test-project",
		Scans:     scans,
	}
}

func TestEstimateTransitionMatrix_Simple(t *testing.T) {
	// 10 scans with known states representing gradual improvement
	readinessScores := []float64{
		5, 8, 15, 25, 30, 45, 50, 72, 80, 96,
	}
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	history := makeScanHistory(readinessScores, baseTime, 7)

	predictor := NewMigrationPredictor()
	T, snapshots, err := predictor.EstimateTransitionMatrix(history)
	if err != nil {
		t.Fatalf("EstimateTransitionMatrix error: %v", err)
	}

	if len(snapshots) != 10 {
		t.Errorf("expected 10 snapshots, got %d", len(snapshots))
	}

	// Verify rows sum to 1
	for i := 0; i < NumStates; i++ {
		rowSum := 0.0
		for j := 0; j < NumStates; j++ {
			rowSum += T[i][j]
		}
		if math.Abs(rowSum-1.0) > 1e-8 {
			t.Errorf("row %d sums to %f, want 1.0", i, rowSum)
		}
	}

	// With Laplace smoothing, no entry should be exactly zero
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			if T[i][j] <= 0 {
				t.Errorf("T[%d][%d] = %f, should be > 0 with Laplace smoothing", i, j, T[i][j])
			}
		}
	}

	// Verify state classifications of the snapshots
	expectedStates := []MigrationState{
		FullyVuln, FullyVuln, MostlyVuln, MostlyVuln, MostlyVuln,
		PartiallyVuln, PartiallyVuln, MostlySafe, MostlySafe, QuantumSafe,
	}
	for i, snap := range snapshots {
		if snap.State != expectedStates[i] {
			t.Errorf("snapshot %d state = %v, want %v (qr=%f)",
				i, snap.State, expectedStates[i], snap.QuantumReadiness)
		}
	}
}

func TestEstimateTransitionMatrix_InsufficientScans(t *testing.T) {
	readiness := []float64{10, 20, 30}
	history := makeScanHistory(readiness, time.Now(), 7)

	predictor := NewMigrationPredictor()
	_, _, err := predictor.EstimateTransitionMatrix(history)
	if err == nil {
		t.Error("expected error for insufficient scans (3 < 5)")
	}
}

func TestStationaryDistribution_AbsorbingState(t *testing.T) {
	// If QuantumSafe is an absorbing state (T[4][4]=1, all others transition
	// toward it), the stationary distribution should converge to pi[4]=1
	var T TransitionMatrix
	T[0][0] = 0.0
	T[0][1] = 1.0
	T[1][1] = 0.0
	T[1][2] = 1.0
	T[2][2] = 0.0
	T[2][3] = 1.0
	T[3][3] = 0.0
	T[3][4] = 1.0
	T[4][4] = 1.0 // absorbing state

	pi := ComputeStationaryDistribution(T)

	// With an absorbing state, all probability mass should end up there
	if math.Abs(pi[4]-1.0) > 1e-6 {
		t.Errorf("stationary dist pi[4] = %f, want 1.0", pi[4])
	}
	for i := 0; i < 4; i++ {
		if math.Abs(pi[i]) > 1e-6 {
			t.Errorf("stationary dist pi[%d] = %f, want 0.0", i, pi[i])
		}
	}
}

func TestExpectedStepsToAbsorb(t *testing.T) {
	// A simple chain where each state transitions to the next with probability 1
	var T TransitionMatrix
	T[0][1] = 1.0
	T[1][2] = 1.0
	T[2][3] = 1.0
	T[3][4] = 1.0
	T[4][4] = 1.0

	steps, err := ExpectedStepsToAbsorb(T, FullyVuln)
	if err != nil {
		t.Fatalf("ExpectedStepsToAbsorb error: %v", err)
	}

	// From FullyVuln (state 0), it takes exactly 4 steps to reach QuantumSafe
	if math.Abs(steps-4.0) > 1e-6 {
		t.Errorf("expected 4 steps from FullyVuln, got %f", steps)
	}

	// From MostlySafe (state 3), it takes exactly 1 step
	steps3, err := ExpectedStepsToAbsorb(T, MostlySafe)
	if err != nil {
		t.Fatalf("ExpectedStepsToAbsorb error: %v", err)
	}
	if math.Abs(steps3-1.0) > 1e-6 {
		t.Errorf("expected 1 step from MostlySafe, got %f", steps3)
	}

	// From QuantumSafe, should be 0
	steps4, err := ExpectedStepsToAbsorb(T, QuantumSafe)
	if err != nil {
		t.Fatalf("ExpectedStepsToAbsorb error: %v", err)
	}
	if steps4 != 0 {
		t.Errorf("expected 0 steps from QuantumSafe, got %f", steps4)
	}

	// Test with a stochastic matrix: result should be positive and finite
	var T2 TransitionMatrix
	T2[0][0] = 0.5
	T2[0][1] = 0.5
	T2[1][1] = 0.3
	T2[1][2] = 0.7
	T2[2][2] = 0.4
	T2[2][3] = 0.6
	T2[3][3] = 0.2
	T2[3][4] = 0.8
	T2[4][4] = 1.0

	stepsStochastic, err := ExpectedStepsToAbsorb(T2, FullyVuln)
	if err != nil {
		t.Fatalf("ExpectedStepsToAbsorb error: %v", err)
	}
	if stepsStochastic <= 0 || math.IsInf(stepsStochastic, 0) || math.IsNaN(stepsStochastic) {
		t.Errorf("expected positive finite steps, got %f", stepsStochastic)
	}
}

func TestCompletionProbability_Monotonic(t *testing.T) {
	// Build a realistic transition matrix
	var T TransitionMatrix
	T[0][0] = 0.6
	T[0][1] = 0.4
	T[1][1] = 0.5
	T[1][2] = 0.5
	T[2][2] = 0.4
	T[2][3] = 0.6
	T[3][3] = 0.3
	T[3][4] = 0.7
	T[4][4] = 1.0

	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	currentState := FullyVuln

	// Probability of being QuantumSafe should increase with time
	var prevProb float64
	for year := 2026; year <= 2035; year++ {
		target := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		prob := CompletionProbabilityByDate(T, currentState, now, target, 7)

		if prob < prevProb-1e-10 {
			t.Errorf("P(safe by %d) = %f < P(safe by %d) = %f: not monotonic",
				year, prob, year-1, prevProb)
		}
		prevProb = prob
	}

	// Far future should approach 1.0 (absorbing state)
	farFuture := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	probFar := CompletionProbabilityByDate(T, currentState, now, farFuture, 7)
	if probFar < 0.99 {
		t.Errorf("P(safe by 2100) = %f, expected close to 1.0", probFar)
	}
}

func TestCompletionProbability_AlreadySafe(t *testing.T) {
	var T TransitionMatrix
	T[4][4] = 1.0

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	target := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	prob := CompletionProbabilityByDate(T, QuantumSafe, now, target, 7)
	if prob != 1.0 {
		t.Errorf("already safe: P = %f, want 1.0", prob)
	}
}

func TestPredict_EndToEnd(t *testing.T) {
	// 20-scan history showing gradual improvement
	readinessScores := []float64{
		5, 7, 8, 12, 15, 20, 25, 30, 35, 42,
		48, 55, 60, 65, 72, 78, 82, 88, 92, 96,
	}
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	history := makeScanHistory(readinessScores, baseTime, 7)

	predictor := NewMigrationPredictor()
	prediction, err := predictor.Predict(history)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}

	// Current state should be QuantumSafe (last score = 96)
	if prediction.CurrentState != QuantumSafe {
		t.Errorf("current state = %v, want QuantumSafe", prediction.CurrentState)
	}

	// State history should have 20 entries
	if len(prediction.StateHistory) != 20 {
		t.Errorf("state history length = %d, want 20", len(prediction.StateHistory))
	}

	// Transition matrix rows should sum to 1
	for i := 0; i < NumStates; i++ {
		rowSum := 0.0
		for j := 0; j < NumStates; j++ {
			rowSum += prediction.TransitionMatrix[i][j]
		}
		if math.Abs(rowSum-1.0) > 1e-8 {
			t.Errorf("transition matrix row %d sums to %f", i, rowSum)
		}
	}

	// Stationary distribution should sum to 1
	piSum := 0.0
	for i := 0; i < NumStates; i++ {
		piSum += prediction.StationaryDist[i]
	}
	if math.Abs(piSum-1.0) > 1e-8 {
		t.Errorf("stationary distribution sums to %f, want 1.0", piSum)
	}

	// Completion probabilities should be present for 2027-2030
	for _, year := range []string{"2027-01-01", "2028-01-01", "2029-01-01", "2030-01-01"} {
		if _, ok := prediction.CompletionByDate[year]; !ok {
			t.Errorf("missing completion probability for %s", year)
		}
	}

	// Confidence should be reasonable with 20 scans
	if prediction.Confidence <= 0 || prediction.Confidence > 1 {
		t.Errorf("confidence = %f, want in (0, 1]", prediction.Confidence)
	}

	// Regression risk should be in [0, 1]
	if prediction.RegressionRisk < 0 || prediction.RegressionRisk > 1 {
		t.Errorf("regression risk = %f, want in [0, 1]", prediction.RegressionRisk)
	}

	// Expected steps should be 0 since we're already at QuantumSafe
	if prediction.ExpectedSteps != 0 {
		t.Errorf("expected steps = %f, want 0 (already quantum safe)", prediction.ExpectedSteps)
	}
}

func TestPredict_PartialProgress(t *testing.T) {
	// History that hasn't reached QuantumSafe yet
	readinessScores := []float64{
		5, 8, 12, 18, 25, 32, 38, 45, 52, 55,
	}
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	history := makeScanHistory(readinessScores, baseTime, 7)

	predictor := NewMigrationPredictor()
	prediction, err := predictor.Predict(history)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}

	// Current state should be PartiallyVuln (last score = 55)
	if prediction.CurrentState != PartiallyVuln {
		t.Errorf("current state = %v, want PartiallyVuln", prediction.CurrentState)
	}

	// Expected steps should be positive (not yet at QuantumSafe)
	if prediction.ExpectedSteps <= 0 {
		t.Errorf("expected steps = %f, should be positive", prediction.ExpectedSteps)
	}

	// Predicted trajectory should have entries
	if len(prediction.PredictedTrajectory) == 0 {
		t.Error("predicted trajectory should not be empty")
	}
}
