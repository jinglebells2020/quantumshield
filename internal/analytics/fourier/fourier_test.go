package fourier

import (
	"math"
	"testing"
)

const tolerance = 1e-6

func almostEqual(a, b, tol float64) bool {
	return math.Abs(a-b) < tol
}

// TestFFT_KnownSignal generates a pure sine wave at a known frequency and
// verifies that the FFT peak falls at the expected bin.
func TestFFT_KnownSignal(t *testing.T) {
	const N = 128
	const freq = 5 // 5 cycles in N samples

	signal := make([]Complex, N)
	for n := 0; n < N; n++ {
		signal[n] = Complex{
			Re: math.Sin(2.0 * math.Pi * float64(freq) * float64(n) / float64(N)),
			Im: 0,
		}
	}

	spectrum := FFT(signal)
	psd := PowerSpectralDensity(spectrum)

	// Find the peak bin (ignoring DC at bin 0).
	peakBin := 1
	peakVal := psd[1]
	for k := 2; k < N/2; k++ {
		if psd[k] > peakVal {
			peakVal = psd[k]
			peakBin = k
		}
	}

	if peakBin != freq {
		t.Errorf("expected peak at bin %d, got bin %d", freq, peakBin)
	}

	// The peak should dominate: at least 100x the average of non-peak bins.
	avgOther := 0.0
	count := 0
	for k := 1; k < N/2; k++ {
		if k != freq {
			avgOther += psd[k]
			count++
		}
	}
	avgOther /= float64(count)
	if peakVal < 100*avgOther {
		t.Errorf("peak not dominant enough: peak=%f, avgOther=%f", peakVal, avgOther)
	}
}

// TestFFT_Inverse verifies that IFFT(FFT(x)) reconstructs the original signal.
func TestFFT_Inverse(t *testing.T) {
	original := []Complex{
		{Re: 1, Im: 0},
		{Re: 2, Im: 1},
		{Re: 3, Im: -1},
		{Re: 4, Im: 0.5},
		{Re: -1, Im: 2},
		{Re: 0, Im: -3},
		{Re: 2.5, Im: 1.5},
		{Re: -0.5, Im: 0},
	}

	spectrum := FFT(original)
	recovered := IFFT(spectrum)

	for i, orig := range original {
		if !almostEqual(orig.Re, recovered[i].Re, tolerance) {
			t.Errorf("Re[%d]: expected %f, got %f", i, orig.Re, recovered[i].Re)
		}
		if !almostEqual(orig.Im, recovered[i].Im, tolerance) {
			t.Errorf("Im[%d]: expected %f, got %f", i, orig.Im, recovered[i].Im)
		}
	}
}

// TestFFT_SingleElement verifies FFT of a single element.
func TestFFT_SingleElement(t *testing.T) {
	input := []Complex{{Re: 42, Im: -7}}
	result := FFT(input)
	if len(result) != 1 {
		t.Fatalf("expected length 1, got %d", len(result))
	}
	if !almostEqual(result[0].Re, 42, tolerance) || !almostEqual(result[0].Im, -7, tolerance) {
		t.Errorf("expected (42, -7), got (%f, %f)", result[0].Re, result[0].Im)
	}
}

// TestPadToPow2 verifies padding behaviour for various input lengths.
func TestPadToPow2(t *testing.T) {
	tests := []struct {
		inputLen   int
		expectedLen int
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{15, 16},
		{16, 16},
		{17, 32},
	}

	for _, tt := range tests {
		input := make([]Complex, tt.inputLen)
		for i := range input {
			input[i] = Complex{Re: float64(i + 1), Im: 0}
		}
		padded := PadToPow2(input)
		if len(padded) != tt.expectedLen {
			t.Errorf("PadToPow2(len=%d): expected len %d, got %d",
				tt.inputLen, tt.expectedLen, len(padded))
		}
		// Verify original data is preserved.
		for i := 0; i < tt.inputLen; i++ {
			if padded[i].Re != float64(i+1) {
				t.Errorf("PadToPow2: data at index %d not preserved", i)
			}
		}
		// Verify padding is zero.
		for i := tt.inputLen; i < tt.expectedLen; i++ {
			if padded[i].Re != 0 || padded[i].Im != 0 {
				t.Errorf("PadToPow2: padding at index %d is not zero", i)
			}
		}
	}
}

// TestSpectralCentroid verifies the spectral centroid for a known distribution.
func TestSpectralCentroid(t *testing.T) {
	// Uniform PSD: centroid should be at the center index.
	n := 8
	uniform := make([]float64, n)
	for i := range uniform {
		uniform[i] = 1.0
	}
	centroid := SpectralCentroid(uniform)
	expected := float64(n-1) / 2.0 // (0+1+2+...+7)/8 = 3.5
	if !almostEqual(centroid, expected, tolerance) {
		t.Errorf("uniform centroid: expected %f, got %f", expected, centroid)
	}

	// Single peak at bin 5: centroid should be 5.
	singlePeak := make([]float64, n)
	singlePeak[5] = 10.0
	centroid = SpectralCentroid(singlePeak)
	if !almostEqual(centroid, 5.0, tolerance) {
		t.Errorf("single-peak centroid: expected 5.0, got %f", centroid)
	}

	// All zeros.
	zeros := make([]float64, n)
	centroid = SpectralCentroid(zeros)
	if centroid != 0 {
		t.Errorf("zero centroid: expected 0, got %f", centroid)
	}
}

// TestSpectralFlatness verifies flatness for uniform and peaked distributions.
func TestSpectralFlatness(t *testing.T) {
	// Uniform PSD should have flatness close to 1.0.
	n := 64
	uniform := make([]float64, n)
	for i := range uniform {
		uniform[i] = 5.0
	}
	flatness := SpectralFlatness(uniform)
	if flatness < 0.95 || flatness > 1.05 {
		t.Errorf("uniform flatness: expected ~1.0, got %f", flatness)
	}

	// Very peaked PSD should have low flatness.
	peaked := make([]float64, n)
	peaked[10] = 100.0
	peaked[11] = 0.01
	flatness = SpectralFlatness(peaked)
	if flatness > 0.1 {
		t.Errorf("peaked flatness: expected <0.1, got %f", flatness)
	}
}

// TestHanningWindow verifies window properties.
func TestHanningWindow(t *testing.T) {
	signal := make([]float64, 64)
	for i := range signal {
		signal[i] = 1.0
	}

	windowed := HanningWindow(signal)

	if len(windowed) != 64 {
		t.Fatalf("expected length 64, got %d", len(windowed))
	}

	// Endpoints of Hanning window should be 0.
	if !almostEqual(windowed[0].Re, 0, tolerance) {
		t.Errorf("window[0] should be 0, got %f", windowed[0].Re)
	}
	if !almostEqual(windowed[len(windowed)-1].Re, 0, tolerance) {
		t.Errorf("window[N-1] should be 0, got %f", windowed[len(windowed)-1].Re)
	}

	// Maximum should be at the center and close to 1.0 (since input is all 1s).
	mid := len(windowed) / 2
	if windowed[mid].Re < 0.95 {
		t.Errorf("window[N/2] should be close to 1.0, got %f", windowed[mid].Re)
	}

	// All imaginary parts should be zero.
	for i, w := range windowed {
		if w.Im != 0 {
			t.Errorf("window[%d].Im should be 0, got %f", i, w.Im)
		}
	}
}

// TestSpectralSpread verifies spread for known distributions.
func TestSpectralSpread(t *testing.T) {
	// Single peak at bin 5: spread should be 0.
	n := 16
	singlePeak := make([]float64, n)
	singlePeak[5] = 10.0
	spread := SpectralSpread(singlePeak)
	if !almostEqual(spread, 0, tolerance) {
		t.Errorf("single-peak spread: expected 0, got %f", spread)
	}

	// Two equal peaks: spread should equal half the distance between them.
	twoPeaks := make([]float64, n)
	twoPeaks[2] = 1.0
	twoPeaks[8] = 1.0
	spread = SpectralSpread(twoPeaks)
	expectedSpread := 3.0 // sqrt((2-5)^2*1 + (8-5)^2*1) / 2) = 3
	if !almostEqual(spread, expectedSpread, tolerance) {
		t.Errorf("two-peak spread: expected %f, got %f", expectedSpread, spread)
	}
}

// TestSpectralRolloff verifies rolloff computation.
func TestSpectralRolloff(t *testing.T) {
	psd := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	// Total = 36, 85% = 30.6
	// Cumulative: 1, 3, 6, 10, 15, 21, 28, 36
	// First >= 30.6 is at index 7.
	rolloff := SpectralRolloff(psd, 0.85)
	if rolloff != 7 {
		t.Errorf("expected rolloff at 7, got %d", rolloff)
	}

	// 50% = 18 -> cumulative first >= 18 is at index 5 (cumsum=21).
	rolloff50 := SpectralRolloff(psd, 0.50)
	if rolloff50 != 5 {
		t.Errorf("expected rolloff at 5, got %d", rolloff50)
	}
}

// TestPeakDetection verifies local maximum detection.
func TestPeakDetection(t *testing.T) {
	psd := []float64{0, 1, 5, 2, 0, 3, 8, 1, 0}
	peaks := PeakDetection(psd, 0.5)

	expected := []int{2, 6}
	if len(peaks) != len(expected) {
		t.Fatalf("expected %d peaks, got %d: %v", len(expected), len(peaks), peaks)
	}
	for i, p := range peaks {
		if p != expected[i] {
			t.Errorf("peak[%d]: expected %d, got %d", i, expected[i], p)
		}
	}

	// With high threshold, only the dominant peak should survive.
	peaks = PeakDetection(psd, 6.0)
	if len(peaks) != 1 || peaks[0] != 6 {
		t.Errorf("with threshold 6.0, expected peak at [6], got %v", peaks)
	}
}

// TestComplexArithmetic verifies Add, Sub, Mul, Conjugate.
func TestComplexArithmetic(t *testing.T) {
	a := Complex{Re: 3, Im: 4}
	b := Complex{Re: 1, Im: -2}

	sum := a.Add(b)
	if sum.Re != 4 || sum.Im != 2 {
		t.Errorf("Add: expected (4,2), got (%f,%f)", sum.Re, sum.Im)
	}

	diff := a.Sub(b)
	if diff.Re != 2 || diff.Im != 6 {
		t.Errorf("Sub: expected (2,6), got (%f,%f)", diff.Re, diff.Im)
	}

	prod := a.Mul(b) // (3+4i)(1-2i) = 3-6i+4i-8i² = 11-2i
	if !almostEqual(prod.Re, 11, tolerance) || !almostEqual(prod.Im, -2, tolerance) {
		t.Errorf("Mul: expected (11,-2), got (%f,%f)", prod.Re, prod.Im)
	}

	conj := a.Conjugate()
	if conj.Re != 3 || conj.Im != -4 {
		t.Errorf("Conjugate: expected (3,-4), got (%f,%f)", conj.Re, conj.Im)
	}

	mag := a.Magnitude()
	if !almostEqual(mag, 5.0, tolerance) {
		t.Errorf("Magnitude: expected 5, got %f", mag)
	}
}

// TestFFT_MultipleFrequencies verifies that two combined sine waves
// produce two distinct peaks.
func TestFFT_MultipleFrequencies(t *testing.T) {
	const N = 256
	f1, f2 := 10, 30

	signal := make([]Complex, N)
	for n := 0; n < N; n++ {
		val := math.Sin(2.0*math.Pi*float64(f1)*float64(n)/float64(N)) +
			0.5*math.Sin(2.0*math.Pi*float64(f2)*float64(n)/float64(N))
		signal[n] = Complex{Re: val, Im: 0}
	}

	spectrum := FFT(signal)
	psd := PowerSpectralDensity(spectrum)

	peaks := PeakDetection(psd[:N/2], 0.01)

	foundF1, foundF2 := false, false
	for _, p := range peaks {
		if p == f1 {
			foundF1 = true
		}
		if p == f2 {
			foundF2 = true
		}
	}
	if !foundF1 {
		t.Errorf("did not find peak at f1=%d, peaks=%v", f1, peaks)
	}
	if !foundF2 {
		t.Errorf("did not find peak at f2=%d, peaks=%v", f2, peaks)
	}
}
