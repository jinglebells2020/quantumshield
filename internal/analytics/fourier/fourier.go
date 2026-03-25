// Package fourier provides pure-Go FFT routines and spectral feature extraction
// for quantum-threat traffic analysis and codebase entropy profiling.
package fourier

import (
	"math"
)

// Complex represents a complex number with real and imaginary parts.
type Complex struct {
	Re, Im float64
}

// Add returns the sum of two complex numbers.
func (c Complex) Add(o Complex) Complex {
	return Complex{Re: c.Re + o.Re, Im: c.Im + o.Im}
}

// Sub returns the difference of two complex numbers.
func (c Complex) Sub(o Complex) Complex {
	return Complex{Re: c.Re - o.Re, Im: c.Im - o.Im}
}

// Mul returns the product of two complex numbers.
func (c Complex) Mul(o Complex) Complex {
	return Complex{
		Re: c.Re*o.Re - c.Im*o.Im,
		Im: c.Re*o.Im + c.Im*o.Re,
	}
}

// Magnitude returns |c| = sqrt(Re² + Im²).
func (c Complex) Magnitude() float64 {
	return math.Sqrt(c.Re*c.Re + c.Im*c.Im)
}

// Conjugate returns the complex conjugate.
func (c Complex) Conjugate() Complex {
	return Complex{Re: c.Re, Im: -c.Im}
}

// isPow2 checks whether n is a power of 2.
func isPow2(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// nextPow2 returns the smallest power of 2 >= n.
func nextPow2(n int) int {
	if isPow2(n) {
		return n
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// bitReverse reverses the lower log2(n) bits of idx.
func bitReverse(idx, log2n int) int {
	rev := 0
	for i := 0; i < log2n; i++ {
		rev = (rev << 1) | (idx & 1)
		idx >>= 1
	}
	return rev
}

// FFT computes the discrete Fourier transform using the iterative
// Cooley-Tukey radix-2 butterfly algorithm. The input length must be a
// power of 2; use PadToPow2 to pad shorter inputs.
func FFT(x []Complex) []Complex {
	n := len(x)
	if n == 0 {
		return nil
	}
	if !isPow2(n) {
		panic("fourier.FFT: input length must be a power of 2")
	}
	if n == 1 {
		return []Complex{x[0]}
	}

	log2n := int(math.Log2(float64(n)))

	// Bit-reversal permutation.
	out := make([]Complex, n)
	for i := 0; i < n; i++ {
		out[bitReverse(i, log2n)] = x[i]
	}

	// Butterfly stages.
	for s := 1; s <= log2n; s++ {
		m := 1 << s      // sub-DFT size at this stage
		half := m >> 1    // half of sub-DFT size
		wm := Complex{    // principal m-th root of unity
			Re: math.Cos(-2.0 * math.Pi / float64(m)),
			Im: math.Sin(-2.0 * math.Pi / float64(m)),
		}
		for k := 0; k < n; k += m {
			w := Complex{Re: 1, Im: 0}
			for j := 0; j < half; j++ {
				t := w.Mul(out[k+j+half])
				u := out[k+j]
				out[k+j] = u.Add(t)
				out[k+j+half] = u.Sub(t)
				w = w.Mul(wm)
			}
		}
	}
	return out
}

// IFFT computes the inverse FFT: conjugate, forward FFT, conjugate, scale by 1/N.
func IFFT(x []Complex) []Complex {
	n := len(x)
	if n == 0 {
		return nil
	}

	// Conjugate input.
	conj := make([]Complex, n)
	for i, v := range x {
		conj[i] = v.Conjugate()
	}

	// Forward FFT.
	result := FFT(conj)

	// Conjugate output and divide by N.
	invN := 1.0 / float64(n)
	for i := range result {
		result[i] = result[i].Conjugate()
		result[i].Re *= invN
		result[i].Im *= invN
	}
	return result
}

// PadToPow2 returns a copy of x padded with zero-valued Complex entries
// to the next power of 2 length. If x is already a power-of-2 length it
// is returned as-is (copied).
func PadToPow2(x []Complex) []Complex {
	n := len(x)
	if n == 0 {
		return []Complex{{}}
	}
	target := nextPow2(n)
	padded := make([]Complex, target)
	copy(padded, x)
	return padded
}

// PowerSpectralDensity computes |X[k]|² / N for each frequency bin.
func PowerSpectralDensity(spectrum []Complex) []float64 {
	n := len(spectrum)
	if n == 0 {
		return nil
	}
	psd := make([]float64, n)
	invN := 1.0 / float64(n)
	for i, v := range spectrum {
		psd[i] = (v.Re*v.Re + v.Im*v.Im) * invN
	}
	return psd
}

// HanningWindow applies a Hann (Hanning) window to a real-valued signal
// and returns it as Complex values:
//
//	w[n] = 0.5 * (1 - cos(2*pi*n / (N-1)))
func HanningWindow(signal []float64) []Complex {
	n := len(signal)
	if n == 0 {
		return nil
	}
	out := make([]Complex, n)
	if n == 1 {
		out[0] = Complex{Re: 0, Im: 0} // window value at single point is 0
		return out
	}
	denom := float64(n - 1)
	for i := 0; i < n; i++ {
		w := 0.5 * (1.0 - math.Cos(2.0*math.Pi*float64(i)/denom))
		out[i] = Complex{Re: signal[i] * w, Im: 0}
	}
	return out
}

// SpectralCentroid computes the "centre of mass" of the power spectrum:
//
//	centroid = sum(k * P[k]) / sum(P[k])
func SpectralCentroid(psd []float64) float64 {
	var num, den float64
	for k, p := range psd {
		num += float64(k) * p
		den += p
	}
	if den == 0 {
		return 0
	}
	return num / den
}

// SpectralSpread computes the standard deviation of frequency around the centroid:
//
//	spread = sqrt( sum( (k - centroid)^2 * P[k] ) / sum(P[k]) )
func SpectralSpread(psd []float64) float64 {
	centroid := SpectralCentroid(psd)
	var num, den float64
	for k, p := range psd {
		diff := float64(k) - centroid
		num += diff * diff * p
		den += p
	}
	if den == 0 {
		return 0
	}
	return math.Sqrt(num / den)
}

// SpectralFlatness computes the Wiener entropy (spectral flatness):
//
//	flatness = exp( mean(log(P)) ) / mean(P)
//
// An epsilon is added to zero-valued PSD bins to avoid log(0).
func SpectralFlatness(psd []float64) float64 {
	n := len(psd)
	if n == 0 {
		return 0
	}
	const epsilon = 1e-12
	var sumLog, sumP float64
	for _, p := range psd {
		v := p
		if v < epsilon {
			v = epsilon
		}
		sumLog += math.Log(v)
		sumP += p + epsilon // consistent epsilon treatment
	}
	meanLog := sumLog / float64(n)
	meanP := sumP / float64(n)
	if meanP == 0 {
		return 0
	}
	return math.Exp(meanLog) / meanP
}

// SpectralRolloff returns the smallest frequency index k such that the
// cumulative PSD sum reaches the given fraction of the total PSD energy.
// fraction is typically 0.85 or 0.95.
func SpectralRolloff(psd []float64, fraction float64) int {
	total := 0.0
	for _, p := range psd {
		total += p
	}
	if total == 0 {
		return 0
	}
	threshold := fraction * total
	cum := 0.0
	for k, p := range psd {
		cum += p
		if cum >= threshold {
			return k
		}
	}
	return len(psd) - 1
}

// PeakDetection finds local maxima in psd that are strictly greater than
// both neighbours and above the given absolute threshold. It returns
// the indices of the detected peaks.
func PeakDetection(psd []float64, threshold float64) []int {
	var peaks []int
	n := len(psd)
	if n < 3 {
		return peaks
	}
	for i := 1; i < n-1; i++ {
		if psd[i] > psd[i-1] && psd[i] > psd[i+1] && psd[i] > threshold {
			peaks = append(peaks, i)
		}
	}
	return peaks
}
