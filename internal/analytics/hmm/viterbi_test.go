package hmm

import (
	"math"
	"testing"
)

// fairBiasedCoinHMM returns a 2-state (fair/biased coin) HMM for testing.
// Uses only the first 2 hidden states and 2 observation types (heads=0, tails=1).
// We map this to our 3-state, 22-obs framework by zeroing out unused entries.
func fairBiasedCoinHMM() HMMParams {
	var p HMMParams

	// Initial: start in Fair state with 60% probability
	p.Initial = [NumHiddenStates]float64{0.6, 0.4, 0.0}

	// Transition:
	//   Fair -> Fair: 0.7,  Fair -> Biased: 0.3
	//   Biased -> Fair: 0.4, Biased -> Biased: 0.6
	//   Neutral is unused
	p.Transition = [NumHiddenStates][NumHiddenStates]float64{
		{0.7, 0.3, 0.0},
		{0.4, 0.6, 0.0},
		{0.0, 0.0, 0.0},
	}

	// Emission (using obs 0=heads, 1=tails):
	//   Fair coin: heads=0.5, tails=0.5
	//   Biased coin: heads=0.8, tails=0.2
	// All other emissions are 0
	p.Emission[HStateSecure][0] = 0.5  // Fair: heads
	p.Emission[HStateSecure][1] = 0.5  // Fair: tails
	p.Emission[HStateInsecure][0] = 0.8 // Biased: heads
	p.Emission[HStateInsecure][1] = 0.2 // Biased: tails

	return p
}

func TestViterbi_KnownSequence(t *testing.T) {
	p := fairBiasedCoinHMM()

	// Observation sequence: lots of heads suggests biased coin
	// H, H, H, T, H, H, H, H, T, H
	obs := []int{0, 0, 0, 1, 0, 0, 0, 0, 1, 0}

	result, err := Viterbi(p, obs)
	if err != nil {
		t.Fatalf("Viterbi returned error: %v", err)
	}

	if len(result.States) != len(obs) {
		t.Fatalf("expected %d states, got %d", len(obs), len(result.States))
	}

	// With this sequence heavy in heads, the biased state (Insecure=1)
	// should dominate. Count how many time steps are decoded as biased.
	biasedCount := 0
	for _, s := range result.States {
		if s == HStateInsecure {
			biasedCount++
		}
	}

	// At least half should be biased given the heavily-heads sequence
	if biasedCount < len(obs)/2 {
		t.Errorf("expected majority biased states, got %d/%d biased", biasedCount, len(obs))
		t.Logf("decoded path: %v", result.States)
	}

	// Log probability should be finite and negative
	if math.IsInf(result.LogProb, 0) || math.IsNaN(result.LogProb) {
		t.Errorf("log probability is not finite: %f", result.LogProb)
	}
	if result.LogProb > 0 {
		t.Errorf("log probability should be negative, got %f", result.LogProb)
	}
}

func TestViterbi_LogProbability(t *testing.T) {
	// Simple 2-state model with known small example
	var p HMMParams
	p.Initial = [NumHiddenStates]float64{0.8, 0.2, 0.0}
	p.Transition = [NumHiddenStates][NumHiddenStates]float64{
		{0.9, 0.1, 0.0},
		{0.3, 0.7, 0.0},
		{0.0, 0.0, 0.0},
	}
	// Emissions for 2 symbols (0 and 1)
	p.Emission[0][0] = 0.6
	p.Emission[0][1] = 0.4
	p.Emission[1][0] = 0.3
	p.Emission[1][1] = 0.7

	obs := []int{0, 1, 0}

	result, err := Viterbi(p, obs)
	if err != nil {
		t.Fatalf("Viterbi returned error: %v", err)
	}

	// Manually compute the log-prob for the expected best path [0, 0, 0]:
	// log(0.8) + log(0.6) + log(0.9) + log(0.4) + log(0.9) + log(0.6)
	expectedLogProb := math.Log(0.8) + math.Log(0.6) + math.Log(0.9) + math.Log(0.4) + math.Log(0.9) + math.Log(0.6)

	if math.Abs(result.LogProb-expectedLogProb) > 1e-10 {
		t.Errorf("log probability mismatch: got %.10f, want %.10f", result.LogProb, expectedLogProb)
	}

	// Verify the decoded path
	expectedStates := []HiddenState{HStateSecure, HStateSecure, HStateSecure}
	for i, s := range result.States {
		if s != expectedStates[i] {
			t.Errorf("state[%d]: got %v, want %v", i, s, expectedStates[i])
		}
	}
}

func TestViterbi_AllSameState(t *testing.T) {
	// Model where state 0 overwhelmingly emits observation 0,
	// and the model strongly stays in state 0.
	var p HMMParams
	p.Initial = [NumHiddenStates]float64{1.0, 0.0, 0.0}
	p.Transition = [NumHiddenStates][NumHiddenStates]float64{
		{1.0, 0.0, 0.0},
		{0.0, 1.0, 0.0},
		{0.0, 0.0, 1.0},
	}
	p.Emission[0][0] = 1.0
	p.Emission[1][1] = 1.0
	p.Emission[2][2] = 1.0

	obs := []int{0, 0, 0, 0, 0}

	result, err := Viterbi(p, obs)
	if err != nil {
		t.Fatalf("Viterbi returned error: %v", err)
	}

	for i, s := range result.States {
		if s != HStateSecure {
			t.Errorf("state[%d]: got %v, want Secure", i, s)
		}
	}

	// Log probability should be log(1^everything) = 0
	if math.Abs(result.LogProb) > 1e-10 {
		t.Errorf("expected log-prob 0 for deterministic model, got %f", result.LogProb)
	}
}

func TestForward_MatchesViterbi(t *testing.T) {
	p := fairBiasedCoinHMM()
	obs := []int{0, 0, 0, 1, 0, 0, 0, 0, 1, 0}

	viterbiResult, err := Viterbi(p, obs)
	if err != nil {
		t.Fatalf("Viterbi error: %v", err)
	}

	forwardLogProb, err := Forward(p, obs)
	if err != nil {
		t.Fatalf("Forward error: %v", err)
	}

	// Forward algorithm marginalizes over all paths, so its probability
	// must be >= the Viterbi (best single path) probability.
	// In log-space: forward log-prob >= viterbi log-prob
	if forwardLogProb < viterbiResult.LogProb-1e-10 {
		t.Errorf("forward log-prob (%.6f) should be >= viterbi log-prob (%.6f)",
			forwardLogProb, viterbiResult.LogProb)
	}

	// Both should be finite and negative
	if math.IsInf(forwardLogProb, 0) || math.IsNaN(forwardLogProb) {
		t.Errorf("forward log-prob not finite: %f", forwardLogProb)
	}
	if forwardLogProb > 0 {
		t.Errorf("forward log-prob should be <= 0, got %f", forwardLogProb)
	}
}

func TestViterbi_EmptySequence(t *testing.T) {
	p := fairBiasedCoinHMM()
	obs := []int{}

	_, err := Viterbi(p, obs)
	if err == nil {
		t.Fatal("expected error for empty sequence, got nil")
	}

	_, err = Forward(p, obs)
	if err == nil {
		t.Fatal("expected error for empty sequence from Forward, got nil")
	}
}

func TestLogSumExp(t *testing.T) {
	// log(exp(-1) + exp(-2) + exp(-3))
	xs := []float64{-1, -2, -3}
	got := logSumExp(xs)
	want := math.Log(math.Exp(-1) + math.Exp(-2) + math.Exp(-3))
	if math.Abs(got-want) > 1e-10 {
		t.Errorf("logSumExp: got %f, want %f", got, want)
	}

	// Edge case: all -Inf
	allNegInf := []float64{math.Inf(-1), math.Inf(-1)}
	got = logSumExp(allNegInf)
	if !math.IsInf(got, -1) {
		t.Errorf("logSumExp of all -Inf: got %f, want -Inf", got)
	}

	// Edge case: empty
	got = logSumExp([]float64{})
	if !math.IsInf(got, -1) {
		t.Errorf("logSumExp of empty: got %f, want -Inf", got)
	}
}

func TestSequenceLogProbability(t *testing.T) {
	p := fairBiasedCoinHMM()
	obs := []int{0, 1, 0}

	lp1, err := Forward(p, obs)
	if err != nil {
		t.Fatalf("Forward error: %v", err)
	}

	lp2, err := SequenceLogProbability(p, obs)
	if err != nil {
		t.Fatalf("SequenceLogProbability error: %v", err)
	}

	if math.Abs(lp1-lp2) > 1e-15 {
		t.Errorf("SequenceLogProbability != Forward: %f vs %f", lp2, lp1)
	}
}
