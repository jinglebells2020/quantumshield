package fourier

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// EntropyAnomaly records a region of a file whose entropy deviates
// significantly from the local average.
type EntropyAnomaly struct {
	Offset      int     `json:"offset"`
	WindowSize  int     `json:"window_size"`
	Entropy     float64 `json:"entropy"`
	Deviation   float64 `json:"deviation_sigma"`
	ContentType string  `json:"content_type"` // "base64", "hex", "pem", "binary", "unknown"
}

// EntropyProfile is the analysis result for a single file or byte slice.
type EntropyProfile struct {
	Path             string           `json:"path,omitempty"`
	Size             int              `json:"size"`
	MeanEntropy      float64          `json:"mean_entropy"`
	StdEntropy       float64          `json:"std_entropy"`
	MinEntropy       float64          `json:"min_entropy"`
	MaxEntropy       float64          `json:"max_entropy"`
	Anomalies        []EntropyAnomaly `json:"anomalies,omitempty"`
	CryptoLikelihood float64          `json:"crypto_likelihood"` // 0..1
	SpectralCentroid float64          `json:"spectral_centroid"`
	SpectralFlatness float64          `json:"spectral_flatness"`
}

// EntropyOption configures an EntropyAnalyzer.
type EntropyOption func(*EntropyAnalyzer)

// WithWindowSize sets the sliding window size (bytes).
func WithWindowSize(size int) EntropyOption {
	return func(a *EntropyAnalyzer) {
		if size > 0 {
			a.windowSize = size
		}
	}
}

// WithStride sets the stride between windows.
func WithStride(stride int) EntropyOption {
	return func(a *EntropyAnalyzer) {
		if stride > 0 {
			a.stride = stride
		}
	}
}

// WithAnomalyStdDev sets the number of standard deviations for anomaly detection.
func WithAnomalyStdDev(n float64) EntropyOption {
	return func(a *EntropyAnalyzer) {
		if n > 0 {
			a.anomalyStdDev = n
		}
	}
}

// WithCryptoThreshold sets the minimum crypto_likelihood for ScanDirectory results.
func WithCryptoThreshold(t float64) EntropyOption {
	return func(a *EntropyAnalyzer) {
		a.cryptoThreshold = t
	}
}

// EntropyAnalyzer performs sliding-window Shannon entropy analysis with
// FFT-based spectral characterisation of the entropy time series.
type EntropyAnalyzer struct {
	windowSize      int
	stride          int
	anomalyStdDev   float64
	cryptoThreshold float64
}

// NewEntropyAnalyzer creates an analyzer with default parameters.
func NewEntropyAnalyzer(opts ...EntropyOption) *EntropyAnalyzer {
	a := &EntropyAnalyzer{
		windowSize:      256,
		stride:          64,
		anomalyStdDev:   2.5,
		cryptoThreshold: 0.5,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// ShannonEntropy computes the byte-level Shannon entropy of data (0..8 bits).
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// SlidingWindowEntropy computes Shannon entropy over a sliding window.
func SlidingWindowEntropy(data []byte, windowSize, stride int) []float64 {
	if len(data) == 0 || windowSize <= 0 || stride <= 0 {
		return nil
	}
	var results []float64
	for offset := 0; offset+windowSize <= len(data); offset += stride {
		window := data[offset : offset+windowSize]
		results = append(results, ShannonEntropy(window))
	}
	return results
}

// AnalyzeBytes performs full entropy analysis on a byte slice.
func (a *EntropyAnalyzer) AnalyzeBytes(data []byte) EntropyProfile {
	profile := EntropyProfile{
		Size: len(data),
	}

	if len(data) == 0 {
		return profile
	}

	// Compute sliding window entropy time series.
	entropySeries := SlidingWindowEntropy(data, a.windowSize, a.stride)
	if len(entropySeries) == 0 {
		profile.MeanEntropy = ShannonEntropy(data)
		profile.MinEntropy = profile.MeanEntropy
		profile.MaxEntropy = profile.MeanEntropy
		return profile
	}

	// Basic statistics of the entropy time series.
	mean, std := seriesStats(entropySeries)
	minE, maxE := seriesMinMax(entropySeries)
	profile.MeanEntropy = mean
	profile.StdEntropy = std
	profile.MinEntropy = minE
	profile.MaxEntropy = maxE

	// Detect anomalies: windows where |H - mean| > anomalyStdDev * std.
	threshold := a.anomalyStdDev * std
	for i, h := range entropySeries {
		deviation := math.Abs(h - mean)
		if deviation > threshold && std > 0 {
			offset := i * a.stride
			contentType := "unknown"
			// Classify high-entropy anomalies.
			if h > mean {
				endPos := offset + a.windowSize
				if endPos > len(data) {
					endPos = len(data)
				}
				contentType = classifyHighEntropy(data[offset:endPos])
			}
			profile.Anomalies = append(profile.Anomalies, EntropyAnomaly{
				Offset:      offset,
				WindowSize:  a.windowSize,
				Entropy:     h,
				Deviation:   deviation / std,
				ContentType: contentType,
			})
		}
	}

	// Apply FFT to entropy time series for spectral characterisation.
	complexSeries := make([]Complex, len(entropySeries))
	for i, e := range entropySeries {
		complexSeries[i] = Complex{Re: e, Im: 0}
	}
	padded := PadToPow2(complexSeries)
	spectrum := FFT(padded)
	psd := PowerSpectralDensity(spectrum)

	profile.SpectralCentroid = SpectralCentroid(psd)
	profile.SpectralFlatness = SpectralFlatness(psd)

	// Compute crypto likelihood as a composite score.
	profile.CryptoLikelihood = computeCryptoLikelihood(profile)

	return profile
}

// AnalyzeFile reads the file at path and performs entropy analysis.
func (a *EntropyAnalyzer) AnalyzeFile(path string) (EntropyProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EntropyProfile{}, fmt.Errorf("reading file %s: %w", path, err)
	}
	profile := a.AnalyzeBytes(data)
	profile.Path = path
	return profile, nil
}

// ScanDirectory walks a directory tree, analysing each file's entropy.
// It skips .git, node_modules, vendor directories and files larger than 10 MB.
// Only files whose crypto_likelihood exceeds the configured threshold
// are included in the results.
func (a *EntropyAnalyzer) ScanDirectory(root string) ([]EntropyProfile, error) {
	const maxFileSize = 10 * 1024 * 1024 // 10 MB

	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
	}

	var results []EntropyProfile

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip files/dirs we can't stat
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}

		profile, err := a.AnalyzeFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		if profile.CryptoLikelihood > a.cryptoThreshold {
			results = append(results, profile)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", root, err)
	}
	return results, nil
}

// classifyHighEntropy attempts to identify the content type of a
// high-entropy region by checking for common encoding patterns.
func classifyHighEntropy(data []byte) string {
	s := string(data)

	// Check for PEM-encoded data.
	if strings.Contains(s, "-----BEGIN") || strings.Contains(s, "-----END") {
		return "pem"
	}

	trimmed := strings.TrimSpace(s)

	// Check for hex encoding before base64 because hex characters are a
	// strict subset of base64 characters and would otherwise be misclassified.
	if len(trimmed) >= 32 && isHexContent(trimmed) {
		return "hex"
	}

	// Check for base64 encoding (at least 32 contiguous base64 characters).
	if len(trimmed) >= 32 && isBase64Content(trimmed) {
		return "base64"
	}

	// Check if it looks like binary (high proportion of non-printable bytes).
	nonPrintable := 0
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	if float64(nonPrintable)/float64(len(data)) > 0.1 {
		return "binary"
	}

	return "unknown"
}

// isBase64Content checks whether s looks like base64 data.
func isBase64Content(s string) bool {
	// Strip whitespace and check if it decodes.
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)

	if len(cleaned) < 32 {
		return false
	}

	// Quick character-set check.
	for _, r := range cleaned {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}

	// Try decoding a chunk.
	chunk := cleaned
	if len(chunk) > 256 {
		chunk = chunk[:256]
	}
	// Pad to multiple of 4.
	for len(chunk)%4 != 0 {
		chunk += "="
	}
	_, err := base64.StdEncoding.DecodeString(chunk)
	return err == nil
}

// isHexContent checks whether s looks like hex-encoded data.
func isHexContent(s string) bool {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ':' {
			return -1
		}
		return r
	}, s)

	if len(cleaned) < 32 || len(cleaned)%2 != 0 {
		return false
	}

	for _, r := range cleaned {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}

	chunk := cleaned
	if len(chunk) > 256 {
		chunk = chunk[:256]
	}
	_, err := hex.DecodeString(chunk)
	return err == nil
}

// computeCryptoLikelihood produces a 0..1 score indicating how likely
// the file contains cryptographic material, based on entropy features.
func computeCryptoLikelihood(p EntropyProfile) float64 {
	score := 0.0

	// High mean entropy (> 6 bits) is a strong crypto indicator.
	if p.MeanEntropy > 7.5 {
		score += 0.35
	} else if p.MeanEntropy > 6.5 {
		score += 0.20
	} else if p.MeanEntropy > 5.5 {
		score += 0.10
	}

	// High max entropy suggests at least some crypto/random regions.
	if p.MaxEntropy > 7.8 {
		score += 0.15
	} else if p.MaxEntropy > 7.0 {
		score += 0.08
	}

	// High-entropy anomalies.
	cryptoAnomalies := 0
	for _, a := range p.Anomalies {
		if a.Entropy > 7.0 {
			cryptoAnomalies++
		}
		if a.ContentType == "base64" || a.ContentType == "hex" || a.ContentType == "pem" {
			score += 0.10
		}
	}
	if cryptoAnomalies > 0 {
		score += math.Min(float64(cryptoAnomalies)*0.05, 0.15)
	}

	// Spectral flatness near 1.0 indicates white-noise-like entropy
	// (typical of encrypted/compressed data).
	if p.SpectralFlatness > 0.85 {
		score += 0.15
	} else if p.SpectralFlatness > 0.6 {
		score += 0.08
	}

	// Large variance relative to mean suggests mixed content with
	// embedded high-entropy regions.
	if p.MeanEntropy > 3 && p.StdEntropy > 1.5 {
		score += 0.10
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// seriesStats returns mean and population standard deviation of a float slice.
func seriesStats(s []float64) (mean, std float64) {
	if len(s) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	mean = sum / float64(len(s))

	sumSq := 0.0
	for _, v := range s {
		d := v - mean
		sumSq += d * d
	}
	std = math.Sqrt(sumSq / float64(len(s)))
	return mean, std
}

// seriesMinMax returns the minimum and maximum values in a float slice.
func seriesMinMax(s []float64) (min, max float64) {
	if len(s) == 0 {
		return 0, 0
	}
	min, max = s[0], s[0]
	for _, v := range s[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}
