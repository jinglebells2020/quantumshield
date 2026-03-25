package montecarlo

import (
	"math"
	"math/rand"
	"sort"
)

// MigrationSimulator holds an RNG for reproducible sampling.
type MigrationSimulator struct {
	rng *rand.Rand
}

// NewMigrationSimulator creates a simulator. Pass optional seed for reproducibility.
func NewMigrationSimulator(seed ...int64) *MigrationSimulator {
	var s int64 = 42
	if len(seed) > 0 {
		s = seed[0]
	}
	return &MigrationSimulator{rng: rand.New(rand.NewSource(s))}
}

// SampleLogNormal draws from LogNormal(mu, sigma). X = exp(mu + sigma*Z) where Z~N(0,1).
func (ms *MigrationSimulator) SampleLogNormal(mu, sigma float64) float64 {
	z := ms.rng.NormFloat64()
	return math.Exp(mu + sigma*z)
}

// SampleExponential draws from Exponential with given mean. Uses inverse CDF: -mean*ln(U).
func (ms *MigrationSimulator) SampleExponential(mean float64) float64 {
	if mean <= 0 {
		return 0
	}
	return -mean * math.Log(1-ms.rng.Float64())
}

// SampleBeta draws from Beta(alpha, beta) using the gamma-ratio method.
func (ms *MigrationSimulator) SampleBeta(alpha, beta float64) float64 {
	if alpha <= 0 || beta <= 0 {
		return 0.5
	}
	x := ms.sampleGamma(alpha)
	y := ms.sampleGamma(beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

func (ms *MigrationSimulator) sampleGamma(shape float64) float64 {
	if shape < 1 {
		u := ms.rng.Float64()
		return ms.sampleGamma(shape+1) * math.Pow(u, 1.0/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = ms.rng.NormFloat64()
			v = 1.0 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := ms.rng.Float64()
		if u < 1-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// SampleBernoulli returns true with probability p.
func (ms *MigrationSimulator) SampleBernoulli(p float64) bool {
	return ms.rng.Float64() < p
}

// Percentile computes the p-th percentile (0-100) of a sorted slice.
func Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := p / 100 * float64(len(sorted)-1)
	lower := int(rank)
	frac := rank - float64(lower)
	if lower+1 >= len(sorted) {
		return sorted[lower]
	}
	return sorted[lower]*(1-frac) + sorted[lower+1]*frac
}

// SortFloat64s sorts a float64 slice in place.
func SortFloat64s(s []float64) {
	sort.Float64s(s)
}
