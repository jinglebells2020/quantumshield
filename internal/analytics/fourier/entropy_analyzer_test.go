package fourier

import (
	"crypto/rand"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShannonEntropy_Uniform verifies that data with all 256 byte values
// equally represented yields maximum entropy (~8.0 bits).
func TestShannonEntropy_Uniform(t *testing.T) {
	// Build data with each byte value appearing the same number of times.
	repeats := 100
	data := make([]byte, 256*repeats)
	for i := 0; i < 256; i++ {
		for j := 0; j < repeats; j++ {
			data[i*repeats+j] = byte(i)
		}
	}

	entropy := ShannonEntropy(data)

	if !almostEqual(entropy, 8.0, 0.01) {
		t.Errorf("uniform entropy: expected ~8.0, got %f", entropy)
	}
}

// TestShannonEntropy_Constant verifies that constant data has zero entropy.
func TestShannonEntropy_Constant(t *testing.T) {
	data := make([]byte, 1024)
	// All zeros by default.

	entropy := ShannonEntropy(data)

	if entropy != 0 {
		t.Errorf("constant entropy: expected 0.0, got %f", entropy)
	}
}

// TestShannonEntropy_English verifies that English ASCII text has entropy
// in the 4-5 bit range.
func TestShannonEntropy_English(t *testing.T) {
	text := `The quick brown fox jumps over the lazy dog.
	Sphinx of black quartz judge my vow.
	How vexingly quick daft zebras jump.
	The five boxing wizards jump quickly.
	Pack my box with five dozen liquor jugs.
	Amazingly few discotheques provide jukeboxes.
	Jackdaws love my big sphinx of quartz.
	We promptly judged antique ivory buckles for the next prize.
	Crazy Frederick bought many very exquisite opal jewels.
	The job requires extra pluck and zeal from every young wage earner.`

	data := []byte(text)
	entropy := ShannonEntropy(data)

	if entropy < 4.0 || entropy > 5.5 {
		t.Errorf("english text entropy: expected 4.0-5.5, got %f", entropy)
	}
}

// TestShannonEntropy_Empty verifies that empty input yields zero.
func TestShannonEntropy_Empty(t *testing.T) {
	entropy := ShannonEntropy(nil)
	if entropy != 0 {
		t.Errorf("empty entropy: expected 0, got %f", entropy)
	}
}

// TestAnalyzeBytes_HighEntropy verifies that random bytes produce
// a high-entropy profile.
func TestAnalyzeBytes_HighEntropy(t *testing.T) {
	data := make([]byte, 16384)
	_, err := rand.Read(data)
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	analyzer := NewEntropyAnalyzer()
	profile := analyzer.AnalyzeBytes(data)

	// Random data with 256-byte sliding windows should have mean entropy > 7.0.
	if profile.MeanEntropy < 7.0 {
		t.Errorf("random data mean entropy: expected >7.0, got %f", profile.MeanEntropy)
	}

	// Max entropy should be high.
	if profile.MaxEntropy < 7.0 {
		t.Errorf("random data max entropy: expected >7.0, got %f", profile.MaxEntropy)
	}

	// Crypto likelihood should be non-trivial for random data.
	if profile.CryptoLikelihood < 0.15 {
		t.Errorf("random data crypto_likelihood: expected >0.15, got %f", profile.CryptoLikelihood)
	}
}

// TestAnalyzeBytes_EmbeddedKey verifies that Go source code with an
// embedded base64 key string triggers an anomaly detection.
func TestAnalyzeBytes_EmbeddedKey(t *testing.T) {
	// Simulate Go source code with low-entropy code and a high-entropy
	// embedded base64 private key string.
	codePrefix := strings.Repeat(`package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}

`, 10) // ~500 bytes of low-entropy code repeated

	// A base64-encoded "key" string - high entropy.
	fakeKey := "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7" +
		"o4qne60x3TqIZhKMjSFRPrGkX5NhV3RF20fZBq7K3bQJ5h8Yz5NB" +
		"M3fYTuLNGenVfAQk6i3brkMbDFezMuoHiPSBiYxWpPjVRmk5Gp8Hi" +
		"6HxDezDqNOhks9JBBmJHzuLVT3HO2JJMnGLR7EZgUPqdMKiN3MU7L" +
		"Z0J5V9Y5kPR9d3HxPFbQjkALRheVq3THzLqLBmGP0ZhAr8DeyQJmL" +
		"D4JKqruIzUnV5GE9R3p68e8z0BAQEFAASCBKgwggSkAgEAAoIBAQC7" +
		"xvBq7K3bQJ5h8Yz5RFg20fZDM3fYTuLNGenVfAQk6i3brkMbDJkWQ"

	codeSuffix := strings.Repeat(`
// Additional code follows
var x = 42
var y = "normal string"
func compute() int {
	return x * x + 1
}
`, 10) // More low-entropy padding.

	source := codePrefix + `
var privateKey = "` + fakeKey + `"
` + codeSuffix

	analyzer := NewEntropyAnalyzer(
		WithWindowSize(256),
		WithStride(64),
		WithAnomalyStdDev(2.0), // slightly more sensitive for test
	)
	profile := analyzer.AnalyzeBytes([]byte(source))

	// We should detect at least one anomaly in the key region.
	if len(profile.Anomalies) == 0 {
		t.Error("expected at least one entropy anomaly for embedded key, got none")
	}

	// At least one anomaly should be classified as base64.
	foundBase64 := false
	for _, a := range profile.Anomalies {
		if a.ContentType == "base64" {
			foundBase64 = true
			break
		}
	}
	if !foundBase64 {
		// Also accept if entropy is high enough for detection.
		foundHighEntropy := false
		for _, a := range profile.Anomalies {
			if a.Entropy > 5.5 {
				foundHighEntropy = true
				break
			}
		}
		if !foundHighEntropy {
			types := make([]string, len(profile.Anomalies))
			for i, a := range profile.Anomalies {
				types[i] = a.ContentType
			}
			t.Errorf("expected base64 or high-entropy anomaly, got types: %v", types)
		}
	}
}

// TestSlidingWindowEntropy_BasicValidation verifies fundamental properties
// of the sliding window computation.
func TestSlidingWindowEntropy_BasicValidation(t *testing.T) {
	// Create data: 512 zero bytes followed by 512 random bytes.
	data := make([]byte, 1024)
	_, err := rand.Read(data[512:])
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	windowSize := 128
	stride := 64
	entropies := SlidingWindowEntropy(data, windowSize, stride)

	expectedCount := (len(data) - windowSize) / stride + 1
	if len(entropies) != expectedCount {
		t.Errorf("expected %d windows, got %d", expectedCount, len(entropies))
	}

	// First few windows (covering only zeros) should have entropy 0.
	for i := 0; i < 5; i++ {
		if entropies[i] != 0 {
			t.Errorf("window[%d] over zeros: expected 0, got %f", i, entropies[i])
		}
	}

	// Last few windows (covering random data) should have high entropy.
	for i := len(entropies) - 3; i < len(entropies); i++ {
		if entropies[i] < 6.0 {
			t.Errorf("window[%d] over random data: expected >6.0, got %f", i, entropies[i])
		}
	}

	// All values should be in [0, 8].
	for i, e := range entropies {
		if e < 0 || e > 8.0+0.001 {
			t.Errorf("window[%d] entropy out of range: %f", i, e)
		}
	}
}

// TestSlidingWindowEntropy_EmptyInput verifies nil is returned for
// empty input.
func TestSlidingWindowEntropy_EmptyInput(t *testing.T) {
	result := SlidingWindowEntropy(nil, 256, 64)
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

// TestSlidingWindowEntropy_WindowLargerThanData verifies behaviour when
// the window is larger than the data.
func TestSlidingWindowEntropy_WindowLargerThanData(t *testing.T) {
	data := []byte("short")
	result := SlidingWindowEntropy(data, 256, 64)
	if result != nil {
		t.Errorf("expected nil when window > data, got length %d", len(result))
	}
}

// TestAnalyzeFile verifies file analysis on a temporary file.
func TestAnalyzeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	// Write random data to the file.
	data := make([]byte, 2048)
	_, err := rand.Read(data)
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	analyzer := NewEntropyAnalyzer()
	profile, err := analyzer.AnalyzeFile(path)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if profile.Path != path {
		t.Errorf("expected path %s, got %s", path, profile.Path)
	}
	if profile.Size != 2048 {
		t.Errorf("expected size 2048, got %d", profile.Size)
	}
	if profile.MeanEntropy < 7.0 {
		t.Errorf("random file mean entropy: expected >7.0, got %f", profile.MeanEntropy)
	}
}

// TestScanDirectory verifies directory scanning with mixed content.
func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create a high-entropy file (should be detected).
	// Use 32KB to ensure reliable high mean entropy across 256-byte windows.
	highEntropyData := make([]byte, 32768)
	_, _ = rand.Read(highEntropyData)
	if err := os.WriteFile(filepath.Join(dir, "encrypted.bin"), highEntropyData, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a low-entropy file (should not be detected).
	lowEntropyData := make([]byte, 4096)
	for i := range lowEntropyData {
		lowEntropyData[i] = byte(i % 4)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), lowEntropyData, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a .git directory that should be skipped.
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "objects"), highEntropyData, 0644); err != nil {
		t.Fatal(err)
	}

	analyzer := NewEntropyAnalyzer(WithCryptoThreshold(0.15))
	results, err := analyzer.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Should find the encrypted file but not the plain text or .git files.
	foundEncrypted := false
	foundGit := false
	for _, r := range results {
		if strings.Contains(r.Path, "encrypted.bin") {
			foundEncrypted = true
		}
		if strings.Contains(r.Path, ".git") {
			foundGit = true
		}
	}

	if !foundEncrypted {
		t.Error("expected to find encrypted.bin in results")
	}
	if foundGit {
		t.Error("should not have scanned .git directory")
	}
}

// TestNewEntropyAnalyzer_Options verifies functional options.
func TestNewEntropyAnalyzer_Options(t *testing.T) {
	a := NewEntropyAnalyzer(
		WithWindowSize(512),
		WithStride(128),
		WithAnomalyStdDev(3.0),
		WithCryptoThreshold(0.7),
	)
	if a.windowSize != 512 {
		t.Errorf("expected windowSize 512, got %d", a.windowSize)
	}
	if a.stride != 128 {
		t.Errorf("expected stride 128, got %d", a.stride)
	}
	if !almostEqual(a.anomalyStdDev, 3.0, 0.001) {
		t.Errorf("expected anomalyStdDev 3.0, got %f", a.anomalyStdDev)
	}
	if !almostEqual(a.cryptoThreshold, 0.7, 0.001) {
		t.Errorf("expected cryptoThreshold 0.7, got %f", a.cryptoThreshold)
	}
}

// TestAnalyzeBytes_LowEntropy verifies that uniform low-entropy data
// does not trigger false positives.
func TestAnalyzeBytes_LowEntropy(t *testing.T) {
	// Repeating pattern: very low entropy.
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 2)
	}

	analyzer := NewEntropyAnalyzer()
	profile := analyzer.AnalyzeBytes(data)

	if profile.MeanEntropy > 2.0 {
		t.Errorf("low-entropy data: expected mean <2.0, got %f", profile.MeanEntropy)
	}
	if profile.CryptoLikelihood > 0.3 {
		t.Errorf("low-entropy data: expected crypto_likelihood <0.3, got %f",
			profile.CryptoLikelihood)
	}
}

// TestClassifyHighEntropy verifies content type classification.
func TestClassifyHighEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "pem",
			data:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBgkq...",
			expected: "pem",
		},
		{
			name:     "hex",
			data:     "4a6f686e20446f652068617320616e20696e746572657374696e67206d657373616765",
			expected: "hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyHighEntropy([]byte(tt.data))
			if result != tt.expected {
				t.Errorf("classifyHighEntropy(%s): expected %q, got %q",
					tt.name, tt.expected, result)
			}
		})
	}
}

// TestSpectralAnalysisOfEntropySeries verifies that the FFT portion
// of AnalyzeBytes produces reasonable spectral features.
func TestSpectralAnalysisOfEntropySeries(t *testing.T) {
	// Create data with a periodic entropy pattern:
	// alternating blocks of zeros and random bytes.
	blockSize := 256
	blocks := 16
	data := make([]byte, blockSize*blocks)
	for b := 0; b < blocks; b++ {
		if b%2 == 1 {
			_, _ = rand.Read(data[b*blockSize : (b+1)*blockSize])
		}
	}

	analyzer := NewEntropyAnalyzer(WithWindowSize(128), WithStride(32))
	profile := analyzer.AnalyzeBytes(data)

	// The periodic pattern should produce a non-zero spectral centroid.
	if profile.SpectralCentroid == 0 {
		t.Error("expected non-zero spectral centroid for periodic data")
	}

	// Spectral flatness should be well below 1.0 (not white noise in entropy).
	if profile.SpectralFlatness > 0.95 {
		t.Errorf("expected spectral flatness < 0.95 for periodic data, got %f",
			profile.SpectralFlatness)
	}

	// Verify min/max entropy span.
	if profile.MaxEntropy-profile.MinEntropy < 3.0 {
		t.Errorf("expected entropy range > 3.0 for mixed data, got %f",
			profile.MaxEntropy-profile.MinEntropy)
	}

	_ = math.Pi // silence potential unused import
}
