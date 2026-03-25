package bayesian

import "math"

// LogOdds converts a probability to log-odds: log(p/(1-p))
func LogOdds(p float64) float64 {
	if p <= 0 {
		return math.Inf(-1)
	}
	if p >= 1 {
		return math.Inf(1)
	}
	return math.Log(p / (1 - p))
}

// FromLogOdds converts log-odds back to probability: 1/(1+exp(-lo))
func FromLogOdds(lo float64) float64 {
	if math.IsInf(lo, 1) {
		return 1
	}
	if math.IsInf(lo, -1) {
		return 0
	}
	return 1.0 / (1.0 + math.Exp(-lo))
}

// BetaUpdate performs conjugate Bayesian update of a Beta(alpha,beta) prior.
// Returns new alpha, beta after observing a success or failure.
func BetaUpdate(alpha, beta float64, success bool) (float64, float64) {
	if success {
		return alpha + 1, beta
	}
	return alpha, beta + 1
}

// BetaMean returns the mean of Beta(alpha,beta) = alpha/(alpha+beta)
func BetaMean(alpha, beta float64) float64 {
	if alpha+beta == 0 {
		return 0.5
	}
	return alpha / (alpha + beta)
}
