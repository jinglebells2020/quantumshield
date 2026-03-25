package markov

import (
	"errors"
	"math"
	"sort"
	"time"

	"quantumshield/pkg/models"
)

// MigrationState represents the quantum-readiness state of a project.
type MigrationState int

const (
	// FullyVuln: quantum readiness < 10%
	FullyVuln MigrationState = iota
	// MostlyVuln: 10% <= quantum readiness < 40%
	MostlyVuln
	// PartiallyVuln: 40% <= quantum readiness < 70%
	PartiallyVuln
	// MostlySafe: 70% <= quantum readiness < 95%
	MostlySafe
	// QuantumSafe: quantum readiness >= 95%
	QuantumSafe
)

// String returns a human-readable label for the migration state.
func (s MigrationState) String() string {
	switch s {
	case FullyVuln:
		return "FullyVulnerable"
	case MostlyVuln:
		return "MostlyVulnerable"
	case PartiallyVuln:
		return "PartiallyVulnerable"
	case MostlySafe:
		return "MostlySafe"
	case QuantumSafe:
		return "QuantumSafe"
	default:
		return "Unknown"
	}
}

// TransitionMatrix is the row-stochastic transition probability matrix
// where T[i][j] = P(next state = j | current state = i).
type TransitionMatrix [NumStates][NumStates]float64

// MigrationStateSnapshot captures the state classification for a single scan.
type MigrationStateSnapshot struct {
	ScanTime         time.Time
	QuantumReadiness float64
	State            MigrationState
}

// MigrationPrediction contains the full output of the migration prediction pipeline.
type MigrationPrediction struct {
	CurrentState         MigrationState
	TransitionMatrix     TransitionMatrix
	StationaryDist       [NumStates]float64
	ExpectedSteps        float64
	CompletionByDate     map[string]float64
	StateHistory         []MigrationStateSnapshot
	RegressionRisk       float64
	Confidence           float64
	EstimatedSafeDate    time.Time
	PredictedTrajectory  []MigrationStateSnapshot
}

// PredictorOption is a functional option for configuring MigrationPredictor.
type PredictorOption func(*MigrationPredictor)

// WithSmoothingAlpha sets the Laplace smoothing parameter.
func WithSmoothingAlpha(alpha float64) PredictorOption {
	return func(p *MigrationPredictor) {
		p.smoothingAlpha = alpha
	}
}

// WithScanIntervalDays sets the expected interval between scans in days.
func WithScanIntervalDays(days int) PredictorOption {
	return func(p *MigrationPredictor) {
		p.scanIntervalDays = days
	}
}

// WithMinScans sets the minimum number of scans required for prediction.
func WithMinScans(n int) PredictorOption {
	return func(p *MigrationPredictor) {
		p.minScans = n
	}
}

// MigrationPredictor uses a Markov chain model to predict the timeline and
// probability of reaching quantum-safe status based on historical scan data.
type MigrationPredictor struct {
	smoothingAlpha  float64
	scanIntervalDays int
	minScans        int
}

// NewMigrationPredictor creates a new predictor with default settings,
// optionally modified by functional options.
func NewMigrationPredictor(opts ...PredictorOption) *MigrationPredictor {
	p := &MigrationPredictor{
		smoothingAlpha:  0.01,
		scanIntervalDays: 7,
		minScans:        5,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ClassifyState maps a quantum readiness score (0-100) to a MigrationState.
func ClassifyState(quantumReadiness float64) MigrationState {
	switch {
	case quantumReadiness >= 95:
		return QuantumSafe
	case quantumReadiness >= 70:
		return MostlySafe
	case quantumReadiness >= 40:
		return PartiallyVuln
	case quantumReadiness >= 10:
		return MostlyVuln
	default:
		return FullyVuln
	}
}

// EstimateTransitionMatrix builds a row-stochastic transition matrix from
// observed state transitions in scan history. Uses Laplace smoothing with
// parameter alpha to avoid zero probabilities. Requires at least minScans scans.
func (p *MigrationPredictor) EstimateTransitionMatrix(history *models.ScanHistory) (TransitionMatrix, []MigrationStateSnapshot, error) {
	if len(history.Scans) < p.minScans {
		return TransitionMatrix{}, nil, errors.New("markov: insufficient scan history, need at least 5 scans")
	}

	// Sort scans by time
	scans := make([]models.ScanResult, len(history.Scans))
	copy(scans, history.Scans)
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt.Before(scans[j].StartedAt)
	})

	// Classify each scan into a state
	snapshots := make([]MigrationStateSnapshot, len(scans))
	for i, scan := range scans {
		snapshots[i] = MigrationStateSnapshot{
			ScanTime:         scan.StartedAt,
			QuantumReadiness: scan.Summary.QuantumReadiness,
			State:            ClassifyState(scan.Summary.QuantumReadiness),
		}
	}

	// Count transitions with Laplace smoothing
	var counts [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			counts[i][j] = p.smoothingAlpha
		}
	}

	for i := 1; i < len(snapshots); i++ {
		from := snapshots[i-1].State
		to := snapshots[i].State
		counts[from][to] += 1.0
	}

	// Normalize rows to get probabilities
	var T TransitionMatrix
	for i := 0; i < NumStates; i++ {
		rowSum := 0.0
		for j := 0; j < NumStates; j++ {
			rowSum += counts[i][j]
		}
		if rowSum > 0 {
			for j := 0; j < NumStates; j++ {
				T[i][j] = counts[i][j] / rowSum
			}
		} else {
			// Uniform distribution fallback (should not happen with smoothing)
			for j := 0; j < NumStates; j++ {
				T[i][j] = 1.0 / float64(NumStates)
			}
		}
	}

	return T, snapshots, nil
}

// ComputeStationaryDistribution finds the stationary distribution pi such that
// pi * T = pi using power iteration. Starts from a uniform distribution and
// iterates until the L-infinity norm of the change drops below 1e-10 or
// 10000 iterations are reached.
func ComputeStationaryDistribution(T TransitionMatrix) [NumStates]float64 {
	const maxIter = 10000
	const tol = 1e-10

	// Start with uniform distribution
	var pi [NumStates]float64
	for i := 0; i < NumStates; i++ {
		pi[i] = 1.0 / float64(NumStates)
	}

	matrix := [NumStates][NumStates]float64(T)

	for iter := 0; iter < maxIter; iter++ {
		next := VectorMatrixMultiply(pi, matrix)
		diff := VectorDiffNorm(pi, next)
		pi = next
		if diff < tol {
			break
		}
	}

	return pi
}

// ExpectedStepsToAbsorb computes the expected number of transition steps to
// reach the QuantumSafe (absorbing) state from each transient state.
// Returns the expected steps from the current state.
//
// The method makes QuantumSafe absorbing by zeroing its row and setting
// the self-transition to 1. It then extracts the Q sub-matrix of transient
// states, computes the fundamental matrix N = (I - Q)^(-1), and sums each
// row of N to get the expected absorption time.
func ExpectedStepsToAbsorb(T TransitionMatrix, currentState MigrationState) (float64, error) {
	absorbingIdx := int(QuantumSafe) // state 4

	// Make a copy and force QuantumSafe to be absorbing
	var P [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			P[i][j] = T[i][j]
		}
	}
	for j := 0; j < NumStates; j++ {
		P[absorbingIdx][j] = 0
	}
	P[absorbingIdx][absorbingIdx] = 1.0

	// Number of transient states (all except QuantumSafe)
	transientCount := NumStates - 1 // 4

	// Extract Q: the transient-to-transient sub-matrix
	Q := make([][]float64, transientCount)
	for i := 0; i < transientCount; i++ {
		Q[i] = make([]float64, transientCount)
		srcRow := i
		if srcRow >= absorbingIdx {
			srcRow++
		}
		for j := 0; j < transientCount; j++ {
			srcCol := j
			if srcCol >= absorbingIdx {
				srcCol++
			}
			Q[i][j] = P[srcRow][srcCol]
		}
	}

	// Compute I - Q
	ImQ := make([][]float64, transientCount)
	for i := 0; i < transientCount; i++ {
		ImQ[i] = make([]float64, transientCount)
		for j := 0; j < transientCount; j++ {
			if i == j {
				ImQ[i][j] = 1.0 - Q[i][j]
			} else {
				ImQ[i][j] = -Q[i][j]
			}
		}
	}

	// Compute N = (I - Q)^(-1)
	N, err := MatrixInverse(ImQ)
	if err != nil {
		return 0, errors.New("markov: cannot compute fundamental matrix, (I-Q) is singular")
	}

	// Sum rows of N to get expected steps to absorption from each transient state
	expectedSteps := make([]float64, transientCount)
	for i := 0; i < transientCount; i++ {
		sum := 0.0
		for j := 0; j < transientCount; j++ {
			sum += N[i][j]
		}
		expectedSteps[i] = sum
	}

	// Map current state to transient index
	if currentState == QuantumSafe {
		return 0, nil // Already absorbed
	}

	idx := int(currentState)
	if idx >= absorbingIdx {
		idx--
	}

	return expectedSteps[idx], nil
}

// CompletionProbabilityByDate computes the probability of being in the
// QuantumSafe state at time targetDate, given the current state and
// transition matrix. Computes P^n where n = ceil((targetDate - now) / interval).
func CompletionProbabilityByDate(T TransitionMatrix, currentState MigrationState, now, targetDate time.Time, intervalDays int) float64 {
	if currentState == QuantumSafe {
		return 1.0
	}

	duration := targetDate.Sub(now)
	if duration <= 0 {
		if currentState == QuantumSafe {
			return 1.0
		}
		return 0.0
	}

	intervalDuration := time.Duration(intervalDays) * 24 * time.Hour
	n := int(math.Ceil(float64(duration) / float64(intervalDuration)))
	if n < 1 {
		n = 1
	}

	// Compute P^n
	Pn := MatrixPower([NumStates][NumStates]float64(T), n)

	// Read the QuantumSafe column for the current state's row
	return Pn[int(currentState)][int(QuantumSafe)]
}

// Predict runs the complete migration prediction pipeline:
//  1. Estimate transition matrix from scan history
//  2. Compute stationary distribution
//  3. Compute expected steps to quantum safety
//  4. Compute completion probabilities for milestone dates (2027-2030)
//  5. Compute regression risk and confidence
func (p *MigrationPredictor) Predict(history *models.ScanHistory) (*MigrationPrediction, error) {
	T, snapshots, err := p.EstimateTransitionMatrix(history)
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return nil, errors.New("markov: no state snapshots generated")
	}

	currentState := snapshots[len(snapshots)-1].State
	now := snapshots[len(snapshots)-1].ScanTime

	// Stationary distribution
	stationaryDist := ComputeStationaryDistribution(T)

	// Expected steps to absorb
	expectedSteps, err := ExpectedStepsToAbsorb(T, currentState)
	if err != nil {
		// Non-fatal: set to NaN if we can't compute
		expectedSteps = math.NaN()
	}

	// Completion probabilities for milestone dates
	completionByDate := make(map[string]float64)
	milestoneYears := []int{2027, 2028, 2029, 2030}
	for _, year := range milestoneYears {
		target := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		prob := CompletionProbabilityByDate(T, currentState, now, target, p.scanIntervalDays)
		dateStr := target.Format("2006-01-02")
		completionByDate[dateStr] = prob
	}

	// Regression risk: probability of moving to a worse state from current
	regressionRisk := 0.0
	if currentState > FullyVuln {
		for j := 0; j < int(currentState); j++ {
			regressionRisk += T[int(currentState)][j]
		}
	}

	// Confidence based on number of observed transitions
	numTransitions := float64(len(snapshots) - 1)
	confidence := 1.0 - math.Exp(-numTransitions/10.0)
	confidence = math.Min(confidence, 0.99)

	// Estimated safe date: find year where P(safe) > 0.5
	estimatedSafeDate := time.Time{}
	if currentState == QuantumSafe {
		estimatedSafeDate = now
	} else {
		for year := now.Year(); year <= now.Year()+50; year++ {
			target := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
			prob := CompletionProbabilityByDate(T, currentState, now, target, p.scanIntervalDays)
			if prob >= 0.5 {
				estimatedSafeDate = target
				break
			}
		}
	}

	// Predicted trajectory: simulate forward for 52 weeks (1 year)
	trajectory := make([]MigrationStateSnapshot, 0)
	simState := [NumStates]float64{}
	simState[int(currentState)] = 1.0
	matrix := [NumStates][NumStates]float64(T)
	for step := 0; step < 52; step++ {
		simState = VectorMatrixMultiply(simState, matrix)
		// Find most probable state
		maxProb := 0.0
		bestState := MigrationState(0)
		for s := 0; s < NumStates; s++ {
			if simState[s] > maxProb {
				maxProb = simState[s]
				bestState = MigrationState(s)
			}
		}
		snapTime := now.Add(time.Duration(step+1) * time.Duration(p.scanIntervalDays) * 24 * time.Hour)
		trajectory = append(trajectory, MigrationStateSnapshot{
			ScanTime: snapTime,
			State:    bestState,
		})
	}

	return &MigrationPrediction{
		CurrentState:        currentState,
		TransitionMatrix:    T,
		StationaryDist:      stationaryDist,
		ExpectedSteps:       expectedSteps,
		CompletionByDate:    completionByDate,
		StateHistory:        snapshots,
		RegressionRisk:      regressionRisk,
		Confidence:          confidence,
		EstimatedSafeDate:   estimatedSafeDate,
		PredictedTrajectory: trajectory,
	}, nil
}
