package hmm

import (
	"errors"
	"math"
)

// ViterbiResult holds the output of the Viterbi algorithm.
type ViterbiResult struct {
	// States is the most likely sequence of hidden states.
	States []HiddenState
	// LogProb is the log-probability of the most likely state sequence.
	LogProb float64
	// StateProbs holds per-timestep log-probabilities for each state.
	// StateProbs[t][s] = log P(best path ending in state s at time t).
	StateProbs [][]float64
}

// Viterbi runs the Viterbi algorithm in log-space to find the most likely
// hidden state sequence given observations and HMM parameters.
func Viterbi(params HMMParams, observations []int) (*ViterbiResult, error) {
	T := len(observations)
	if T == 0 {
		return nil, errors.New("hmm: empty observation sequence")
	}
	N := NumHiddenStates

	// Validate observations
	for t, obs := range observations {
		if obs < 0 || obs >= NumAPICallTypes {
			return nil, errors.New("hmm: observation out of range at position " + itoa(t))
		}
	}

	// dp[t][s] = log probability of the best path ending in state s at time t
	dp := make([][]float64, T)
	// backptr[t][s] = previous state on the best path to state s at time t
	backptr := make([][]int, T)
	for t := 0; t < T; t++ {
		dp[t] = make([]float64, N)
		backptr[t] = make([]int, N)
	}

	// Initialization: dp[0][s] = log(π[s]) + log(B[s][obs_0])
	obs0 := observations[0]
	for s := 0; s < N; s++ {
		dp[0][s] = safeLog(params.Initial[s]) + safeLog(params.Emission[s][obs0])
		backptr[0][s] = -1
	}

	// Recursion: dp[t][s] = max_r { dp[t-1][r] + log(A[r][s]) } + log(B[s][obs_t])
	for t := 1; t < T; t++ {
		obs := observations[t]
		for s := 0; s < N; s++ {
			bestLogProb := math.Inf(-1)
			bestPrev := 0
			for r := 0; r < N; r++ {
				lp := dp[t-1][r] + safeLog(params.Transition[r][s])
				if lp > bestLogProb {
					bestLogProb = lp
					bestPrev = r
				}
			}
			dp[t][s] = bestLogProb + safeLog(params.Emission[s][obs])
			backptr[t][s] = bestPrev
		}
	}

	// Termination: find the state with highest log-prob at time T-1
	bestFinalState := 0
	bestFinalLogProb := dp[T-1][0]
	for s := 1; s < N; s++ {
		if dp[T-1][s] > bestFinalLogProb {
			bestFinalLogProb = dp[T-1][s]
			bestFinalState = s
		}
	}

	// Backtracking
	states := make([]HiddenState, T)
	states[T-1] = HiddenState(bestFinalState)
	for t := T - 2; t >= 0; t-- {
		states[t] = HiddenState(backptr[t+1][int(states[t+1])])
	}

	return &ViterbiResult{
		States:     states,
		LogProb:    bestFinalLogProb,
		StateProbs: dp,
	}, nil
}

// Forward runs the forward algorithm to compute the total log-probability
// of the observation sequence given the model: log P(obs | model).
// Uses log-sum-exp for numerical stability.
func Forward(params HMMParams, observations []int) (float64, error) {
	T := len(observations)
	if T == 0 {
		return 0, errors.New("hmm: empty observation sequence")
	}
	N := NumHiddenStates

	for t, obs := range observations {
		if obs < 0 || obs >= NumAPICallTypes {
			return 0, errors.New("hmm: observation out of range at position " + itoa(t))
		}
	}

	// alpha[s] = log P(obs_0..obs_t, state_t = s)
	alpha := make([]float64, N)
	newAlpha := make([]float64, N)

	// Initialization
	obs0 := observations[0]
	for s := 0; s < N; s++ {
		alpha[s] = safeLog(params.Initial[s]) + safeLog(params.Emission[s][obs0])
	}

	// Induction
	for t := 1; t < T; t++ {
		obs := observations[t]
		for s := 0; s < N; s++ {
			// newAlpha[s] = log( Σ_r exp(alpha[r] + log A[r][s]) ) + log B[s][obs]
			terms := make([]float64, N)
			for r := 0; r < N; r++ {
				terms[r] = alpha[r] + safeLog(params.Transition[r][s])
			}
			newAlpha[s] = logSumExp(terms) + safeLog(params.Emission[s][obs])
		}
		alpha, newAlpha = newAlpha, alpha
	}

	// Termination: log P(obs) = log Σ_s exp(alpha_T[s])
	return logSumExp(alpha), nil
}

// SequenceLogProbability returns the log-probability of the observation
// sequence under the given HMM parameters. This is a convenience wrapper
// around Forward.
func SequenceLogProbability(params HMMParams, observations []int) (float64, error) {
	return Forward(params, observations)
}

// logSumExp computes log(Σ exp(x_i)) in a numerically stable way.
func logSumExp(xs []float64) float64 {
	if len(xs) == 0 {
		return math.Inf(-1)
	}

	// Find the maximum value
	maxVal := xs[0]
	for _, x := range xs[1:] {
		if x > maxVal {
			maxVal = x
		}
	}

	// If max is -Inf, all values are -Inf
	if math.IsInf(maxVal, -1) {
		return math.Inf(-1)
	}

	// log(Σ exp(x_i)) = max + log(Σ exp(x_i - max))
	var sum float64
	for _, x := range xs {
		sum += math.Exp(x - maxVal)
	}
	return maxVal + math.Log(sum)
}

// safeLog returns log(x), mapping 0 to -Inf.
func safeLog(x float64) float64 {
	if x <= 0 {
		return math.Inf(-1)
	}
	return math.Log(x)
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	if neg {
		digits = append(digits, '-')
	}
	// Reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
