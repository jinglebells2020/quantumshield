package information

import "math"

// ShannonEntropy computes H(X) = -Σ p(x)·log2(p(x)) for a frequency distribution.
// Returns entropy in bits. Handles p(x)=0 by convention 0·log(0)=0.
func ShannonEntropy(frequencies map[int]int, totalCount int) float64 {
	if totalCount == 0 {
		return 0
	}
	var h float64
	for _, count := range frequencies {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(totalCount)
		h -= p * math.Log2(p)
	}
	return h
}

// KLDivergence computes D_KL(P || Q) = Σ P(x)·log(P(x)/Q(x)).
// Convention: 0·log(0/q) = 0. Adds epsilon=1e-300 to Q to avoid division by zero.
func KLDivergence(P, Q []float64) float64 {
	if len(P) != len(Q) {
		return math.Inf(1)
	}
	const epsilon = 1e-300
	var kl float64
	for i := range P {
		if P[i] == 0 {
			continue
		}
		q := Q[i]
		if q == 0 {
			q = epsilon
		}
		kl += P[i] * math.Log(P[i]/q)
	}
	return kl
}

// ChiSquaredTest performs Pearson's chi-squared goodness-of-fit test.
// Returns chi-squared statistic and approximate p-value.
func ChiSquaredTest(observed []int, expected []float64) (chiSq float64, pValue float64) {
	if len(observed) != len(expected) {
		return 0, 1
	}
	for i := range observed {
		if expected[i] == 0 {
			continue
		}
		diff := float64(observed[i]) - expected[i]
		chiSq += diff * diff / expected[i]
	}
	df := float64(len(observed) - 1)
	if df <= 0 {
		return chiSq, 1
	}
	pValue = 1 - chiSquaredCDF(chiSq, df)
	if pValue < 0 {
		pValue = 0
	}
	return chiSq, pValue
}

// chiSquaredCDF approximates the chi-squared CDF using the regularized incomplete gamma function.
func chiSquaredCDF(x, df float64) float64 {
	if x <= 0 {
		return 0
	}
	return IncompleteGamma(df/2, x/2)
}

// WaldWolfowitzRunsTest tests for randomness in a byte sequence.
// Computes runs of values above/below the median and returns z-statistic and p-value.
func WaldWolfowitzRunsTest(data []byte) (zStat float64, pValue float64) {
	if len(data) < 20 {
		return 0, 1
	}
	sorted := make([]byte, len(data))
	copy(sorted, data)
	sortBytes(sorted)
	median := sorted[len(sorted)/2]

	var n1, n2, runs int
	var lastAbove bool
	for i, b := range data {
		above := b > median
		if b == median {
			above = i%2 == 0
		}
		if above {
			n1++
		} else {
			n2++
		}
		if i == 0 || above != lastAbove {
			runs++
		}
		lastAbove = above
	}

	if n1 == 0 || n2 == 0 {
		return 0, 1
	}

	n := float64(n1 + n2)
	fn1, fn2 := float64(n1), float64(n2)
	expectedRuns := 1 + 2*fn1*fn2/n
	varianceRuns := 2 * fn1 * fn2 * (2*fn1*fn2 - n) / (n * n * (n - 1))
	if varianceRuns <= 0 {
		return 0, 1
	}

	zStat = (float64(runs) - expectedRuns) / math.Sqrt(varianceRuns)
	pValue = 2 * (1 - NormalCDF(math.Abs(zStat)))
	return zStat, pValue
}

// MonoBitTest implements the NIST SP 800-22 monobit (frequency) test.
// Returns p-value testing whether proportion of 1-bits differs from 0.5.
func MonoBitTest(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var ones int
	for _, b := range data {
		for bit := 0; bit < 8; bit++ {
			if (b>>uint(bit))&1 == 1 {
				ones++
			}
		}
	}
	n := float64(len(data) * 8)
	s := math.Abs(float64(ones) - n/2)
	sObs := s / math.Sqrt(n/2)
	return math.Erfc(sObs / math.Sqrt(2))
}

// SerialCorrelation computes the lag-1 autocorrelation coefficient of byte values.
func SerialCorrelation(data []byte) float64 {
	n := len(data)
	if n < 2 {
		return 0
	}
	var sumX, sumX2, sumXY float64
	for i := 0; i < n; i++ {
		x := float64(data[i])
		sumX += x
		sumX2 += x * x
		if i < n-1 {
			sumXY += x * float64(data[i+1])
		}
	}
	fn := float64(n)
	fn1 := float64(n - 1)
	denom := fn*sumX2 - sumX*sumX
	if denom == 0 {
		return 0
	}
	return (fn1*sumXY - sumX*(sumX-float64(data[0]))) / denom
}

// NormalCDF computes the CDF of N(0,1) using the Abramowitz and Stegun approximation.
func NormalCDF(x float64) float64 {
	return 0.5 * math.Erfc(-x/math.Sqrt(2))
}

// IncompleteGamma computes the regularized lower incomplete gamma function P(a, x)
// using the series expansion for small x and continued fraction for large x.
func IncompleteGamma(a, x float64) float64 {
	if x < 0 || a <= 0 {
		return 0
	}
	if x == 0 {
		return 0
	}
	if x < a+1 {
		return gammaSeries(a, x)
	}
	return 1 - gammaCF(a, x)
}

func gammaSeries(a, x float64) float64 {
	gln := lgamma(a)
	ap := a
	sum := 1.0 / a
	del := sum
	for n := 1; n <= 200; n++ {
		ap++
		del *= x / ap
		sum += del
		if math.Abs(del) < math.Abs(sum)*1e-14 {
			break
		}
	}
	return sum * math.Exp(-x+a*math.Log(x)-gln)
}

func gammaCF(a, x float64) float64 {
	gln := lgamma(a)
	b := x + 1 - a
	c := 1.0 / 1e-30
	d := 1.0 / b
	h := d
	for i := 1; i <= 200; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < 1e-30 {
			d = 1e-30
		}
		c = b + an/c
		if math.Abs(c) < 1e-30 {
			c = 1e-30
		}
		d = 1.0 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-14 {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-gln) * h
}

func lgamma(x float64) float64 {
	v, _ := math.Lgamma(x)
	return v
}

func sortBytes(b []byte) {
	// Simple counting sort for bytes (0-255)
	var counts [256]int
	for _, v := range b {
		counts[v]++
	}
	idx := 0
	for v := 0; v < 256; v++ {
		for i := 0; i < counts[v]; i++ {
			b[idx] = byte(v)
			idx++
		}
	}
}
