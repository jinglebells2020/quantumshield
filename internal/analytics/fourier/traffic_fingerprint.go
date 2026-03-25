package fourier

import (
	"fmt"
	"math"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// CipherSuiteFingerprint holds the spectral and statistical features that
// characterise TLS handshake traffic for a particular cipher suite family.
type CipherSuiteFingerprint struct {
	SpectralCentroid  float64 `json:"spectral_centroid"`
	SpectralSpread    float64 `json:"spectral_spread"`
	SpectralFlatness  float64 `json:"spectral_flatness"`
	SpectralRolloff85 float64 `json:"spectral_rolloff_85"`
	MeanDuration      float64 `json:"mean_duration_ms"`
	StdDuration       float64 `json:"std_duration_ms"`
	DominantFreqBin   int     `json:"dominant_freq_bin"`
}

// featureVector returns a normalised vector of the fingerprint fields for
// cosine similarity computation.
func (f CipherSuiteFingerprint) featureVector() []float64 {
	return []float64{
		f.SpectralCentroid,
		f.SpectralSpread,
		f.SpectralFlatness,
		f.SpectralRolloff85,
		f.MeanDuration,
		f.StdDuration,
	}
}

// CipherSuiteClassification is the result of classifying an observed
// fingerprint against known cipher suite families.
type CipherSuiteClassification struct {
	Endpoint         string                   `json:"endpoint"`
	CipherSuiteGroup string                   `json:"cipher_suite_group"`
	Similarity       float64                  `json:"similarity"`
	QuantumThreat    models.QuantumThreatLevel `json:"quantum_threat"`
	Fingerprint      CipherSuiteFingerprint   `json:"fingerprint"`
	HandshakeCount   int                      `json:"handshake_count"`
	AnalyzedAt       time.Time                `json:"analyzed_at"`
}

// TrafficFingerprinter analyses TLS handshake inter-arrival patterns
// to classify cipher suites via spectral fingerprinting.
type TrafficFingerprinter struct {
	knownFingerprints map[string]CipherSuiteFingerprint
	minSamples        int
}

// NewTrafficFingerprinter creates a fingerprinter pre-loaded with known
// spectral signatures for common cipher suite families.
func NewTrafficFingerprinter() *TrafficFingerprinter {
	known := map[string]CipherSuiteFingerprint{
		"RSA-2048": {
			SpectralCentroid:  5.0,
			SpectralSpread:    3.0,
			SpectralFlatness:  0.3,
			SpectralRolloff85: 12.0,
			MeanDuration:      3.5,
			StdDuration:       1.2,
			DominantFreqBin:   4,
		},
		"ECDHE-P256": {
			SpectralCentroid:  8.0,
			SpectralSpread:    1.5,
			SpectralFlatness:  0.5,
			SpectralRolloff85: 10.0,
			MeanDuration:      0.7,
			StdDuration:       0.3,
			DominantFreqBin:   8,
		},
		"ML-KEM-768": {
			SpectralCentroid:  10.0,
			SpectralSpread:    0.8,
			SpectralFlatness:  0.85,
			SpectralRolloff85: 11.0,
			MeanDuration:      0.2,
			StdDuration:       0.05,
			DominantFreqBin:   10,
		},
		"DH-2048": {
			SpectralCentroid:  3.0,
			SpectralSpread:    4.0,
			SpectralFlatness:  0.2,
			SpectralRolloff85: 14.0,
			MeanDuration:      5.5,
			StdDuration:       2.0,
			DominantFreqBin:   3,
		},
		"ECDHE-P384": {
			SpectralCentroid:  7.5,
			SpectralSpread:    1.8,
			SpectralFlatness:  0.45,
			SpectralRolloff85: 10.0,
			MeanDuration:      1.0,
			StdDuration:       0.4,
			DominantFreqBin:   7,
		},
		"RSA-4096": {
			SpectralCentroid:  4.0,
			SpectralSpread:    3.5,
			SpectralFlatness:  0.25,
			SpectralRolloff85: 13.0,
			MeanDuration:      6.0,
			StdDuration:       2.5,
			DominantFreqBin:   3,
		},
	}
	return &TrafficFingerprinter{
		knownFingerprints: known,
		minSamples:        30,
	}
}

// BuildFingerprint extracts spectral features from a set of TLS handshakes.
// It requires at least minSamples handshakes to produce a reliable fingerprint.
func (tf *TrafficFingerprinter) BuildFingerprint(handshakes []models.TLSHandshake) (CipherSuiteFingerprint, error) {
	if len(handshakes) < tf.minSamples {
		return CipherSuiteFingerprint{}, fmt.Errorf(
			"insufficient handshakes: got %d, need at least %d", len(handshakes), tf.minSamples)
	}

	// Collect inter-arrival times from all handshakes.
	var allInterArrivals []float64
	for _, h := range handshakes {
		allInterArrivals = append(allInterArrivals, h.InterArrivalMs...)
	}

	if len(allInterArrivals) == 0 {
		return CipherSuiteFingerprint{}, fmt.Errorf("no inter-arrival data in handshakes")
	}

	// Apply Hanning window.
	windowed := HanningWindow(allInterArrivals)

	// Pad to power of 2 and run FFT.
	padded := PadToPow2(windowed)
	spectrum := FFT(padded)

	// Compute power spectral density.
	psd := PowerSpectralDensity(spectrum)

	// Extract spectral features.
	centroid := SpectralCentroid(psd)
	spread := SpectralSpread(psd)
	flatness := SpectralFlatness(psd)
	rolloff := SpectralRolloff(psd, 0.85)

	// Find dominant frequency bin.
	dominantBin := 0
	maxPSD := 0.0
	for i, p := range psd {
		if p > maxPSD {
			maxPSD = p
			dominantBin = i
		}
	}

	// Compute handshake duration statistics.
	meanDur, stdDur := durationStats(handshakes)

	return CipherSuiteFingerprint{
		SpectralCentroid:  centroid,
		SpectralSpread:    spread,
		SpectralFlatness:  flatness,
		SpectralRolloff85: float64(rolloff),
		MeanDuration:      meanDur,
		StdDuration:       stdDur,
		DominantFreqBin:   dominantBin,
	}, nil
}

// ClassifyCipherSuite matches an observed fingerprint against all known
// fingerprints using cosine similarity and returns the best match.
// Returns an empty string and 0 similarity if no known fingerprint
// exceeds the 0.75 similarity threshold.
func (tf *TrafficFingerprinter) ClassifyCipherSuite(fp CipherSuiteFingerprint) (string, float64) {
	observed := fp.featureVector()

	bestName := ""
	bestSim := 0.0

	for name, known := range tf.knownFingerprints {
		ref := known.featureVector()
		sim := cosineSimilarity(observed, ref)
		if sim > bestSim {
			bestSim = sim
			bestName = name
		}
	}

	if bestSim < 0.75 {
		return "", bestSim
	}
	return bestName, bestSim
}

// DetectQuantumVulnerableSuites groups handshakes by server endpoint,
// builds a fingerprint for each group, classifies the cipher suite,
// and flags suites that are quantum-vulnerable.
func (tf *TrafficFingerprinter) DetectQuantumVulnerableSuites(
	handshakes []models.TLSHandshake,
) []CipherSuiteClassification {
	// Group by endpoint (server_ip:server_port).
	groups := make(map[string][]models.TLSHandshake)
	for _, h := range handshakes {
		endpoint := fmt.Sprintf("%s:%d", h.ServerIP, h.ServerPort)
		groups[endpoint] = append(groups[endpoint], h)
	}

	var results []CipherSuiteClassification

	for endpoint, hGroup := range groups {
		fp, err := tf.BuildFingerprint(hGroup)
		if err != nil {
			continue
		}

		suiteName, similarity := tf.ClassifyCipherSuite(fp)
		if suiteName == "" {
			suiteName = "UNKNOWN"
		}

		threat := classifyQuantumThreat(suiteName)

		results = append(results, CipherSuiteClassification{
			Endpoint:         endpoint,
			CipherSuiteGroup: suiteName,
			Similarity:       similarity,
			QuantumThreat:    threat,
			Fingerprint:      fp,
			HandshakeCount:   len(hGroup),
			AnalyzedAt:       time.Now(),
		})
	}

	return results
}

// isQuantumVulnerable returns true if the cipher suite name indicates a
// quantum-vulnerable key exchange (RSA, ECDHE, or DH) without a
// post-quantum hybrid (ML-KEM).
func isQuantumVulnerable(suite string) bool {
	upper := strings.ToUpper(suite)
	if strings.Contains(upper, "ML-KEM") {
		return false
	}
	vulnerable := []string{"RSA", "ECDHE", "DH"}
	for _, v := range vulnerable {
		if strings.Contains(upper, v) {
			return true
		}
	}
	return false
}

// classifyQuantumThreat maps a cipher suite name to a QuantumThreatLevel.
func classifyQuantumThreat(suite string) models.QuantumThreatLevel {
	if !isQuantumVulnerable(suite) {
		return models.ThreatNotDirectlyThreatened
	}
	return models.ThreatBrokenByShor
}

// cosineSimilarity computes the cosine similarity between two vectors.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, magA, magB float64
	for i := range a {
		dot += a[i] * b[i]
		magA += a[i] * a[i]
		magB += b[i] * b[i]
	}
	denom := math.Sqrt(magA) * math.Sqrt(magB)
	if denom == 0 {
		return 0
	}
	return dot / denom
}

// durationStats computes the mean and standard deviation of handshake durations.
func durationStats(handshakes []models.TLSHandshake) (mean, std float64) {
	if len(handshakes) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, h := range handshakes {
		sum += h.HandshakeDurMs
	}
	mean = sum / float64(len(handshakes))

	sumSq := 0.0
	for _, h := range handshakes {
		d := h.HandshakeDurMs - mean
		sumSq += d * d
	}
	std = math.Sqrt(sumSq / float64(len(handshakes)))
	return mean, std
}
