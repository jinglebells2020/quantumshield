package hmm

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"quantumshield/pkg/models"
)

// ObservedAPICall represents a crypto API call extracted from source code.
type ObservedAPICall struct {
	// Name is the matched API call pattern (e.g. "rsa.GenerateKey").
	Name string
	// APICallType is the corresponding HMM observation constant.
	APICallType int
	// Line is the 1-based line number where the call was found.
	Line int
	// FilePath is the source file containing the call.
	FilePath string
}

// VulnerabilityPattern describes a detected vulnerability from HMM analysis.
type VulnerabilityPattern struct {
	// Finding is the QuantumShield finding generated from this pattern.
	Finding models.Finding
	// LogLikelihoodRatio is the LLR (insecure model vs secure model).
	LogLikelihoodRatio float64
	// InsecureRunStart is the index of the first observation in the insecure run.
	InsecureRunStart int
	// InsecureRunEnd is the index past the last observation in the insecure run.
	InsecureRunEnd int
	// APICallTypes lists the observation types in the insecure run.
	APICallTypes []int
}

// DetectorOption configures a PatternDetector.
type DetectorOption func(*PatternDetector)

// WithThreshold sets the log-likelihood ratio threshold for flagging patterns.
func WithThreshold(t float64) DetectorOption {
	return func(pd *PatternDetector) {
		pd.threshold = t
	}
}

// WithInsecureModel overrides the default insecure HMM parameters.
func WithInsecureModel(p HMMParams) DetectorOption {
	return func(pd *PatternDetector) {
		pd.insecureModel = p
	}
}

// WithSecureModel overrides the default secure HMM parameters.
func WithSecureModel(p HMMParams) DetectorOption {
	return func(pd *PatternDetector) {
		pd.secureModel = p
	}
}

// PatternDetector uses two HMMs (insecure vs secure) to detect
// cryptographic vulnerability patterns in sequences of API calls.
// Module 9: HMM-based crypto usage pattern analysis.
type PatternDetector struct {
	insecureModel HMMParams
	secureModel   HMMParams
	threshold     float64
}

// NewPatternDetector creates a PatternDetector initialized with domain-knowledge
// HMM parameters for insecure and secure crypto usage patterns.
func NewPatternDetector(opts ...DetectorOption) *PatternDetector {
	pd := &PatternDetector{
		threshold: 2.0,
	}

	// --- Insecure model ---
	// Initial: likely starts in insecure state
	pd.insecureModel.Initial = [NumHiddenStates]float64{0.1, 0.7, 0.2}

	// Transition: insecure state is sticky (0.7 self-loop)
	pd.insecureModel.Transition = [NumHiddenStates][NumHiddenStates]float64{
		{0.6, 0.2, 0.2},  // Secure -> ...
		{0.1, 0.7, 0.2},  // Insecure -> Insecure (sticky)
		{0.2, 0.3, 0.5},  // Neutral -> ...
	}

	// Emission: insecure state has high emission for RSA/ECDSA/ECDH
	pd.insecureModel.Emission = buildInsecureEmission()

	// --- Secure model ---
	// Initial: likely starts in secure state
	pd.secureModel.Initial = [NumHiddenStates]float64{0.7, 0.1, 0.2}

	// Transition: secure state is sticky (0.8 self-loop)
	pd.secureModel.Transition = [NumHiddenStates][NumHiddenStates]float64{
		{0.8, 0.05, 0.15}, // Secure -> Secure (sticky)
		{0.3, 0.4, 0.3},   // Insecure -> ...
		{0.3, 0.2, 0.5},   // Neutral -> ...
	}

	// Emission: secure state has high emission for MLKEM/MLDSA/AESGCM
	pd.secureModel.Emission = buildSecureEmission()

	for _, opt := range opts {
		opt(pd)
	}

	return pd
}

// buildInsecureEmission constructs emission probabilities for the insecure model.
// Insecure state (1) strongly emits RSA, ECDSA, ECDH calls.
func buildInsecureEmission() [NumHiddenStates][NumAPICallTypes]float64 {
	var e [NumHiddenStates][NumAPICallTypes]float64

	// Secure state: moderate emission across post-quantum and AES-GCM
	e[HStateSecure] = uniformEmission()
	e[HStateSecure][APICallMLKEMEncapsulate] = 0.15
	e[HStateSecure][APICallMLDSASign] = 0.10
	e[HStateSecure][APICallMLDSAVerify] = 0.10
	e[HStateSecure][APICallAESGCM] = 0.10
	normalizeRow(&e[HStateSecure])

	// Insecure state: high emission for classical pre-quantum algorithms
	// and unauthenticated symmetric modes (CFB, CBC without GCM)
	e[HStateInsecure] = uniformEmission()
	e[HStateInsecure][APICallRSAGenerateKey] = 0.12
	e[HStateInsecure][APICallRSAEncrypt] = 0.10
	e[HStateInsecure][APICallRSADecrypt] = 0.08
	e[HStateInsecure][APICallRSASign] = 0.08
	e[HStateInsecure][APICallECDSAGenerateKey] = 0.08
	e[HStateInsecure][APICallECDSASign] = 0.08
	e[HStateInsecure][APICallECDSAVerify] = 0.04
	e[HStateInsecure][APICallECDHGenerateKey] = 0.06
	e[HStateInsecure][APICallECDHSharedKey] = 0.05
	e[HStateInsecure][APICallAESNewCipher] = 0.08
	e[HStateInsecure][APICallAESCBC] = 0.10
	e[HStateInsecure][APICallAESCFB] = 0.10
	normalizeRow(&e[HStateInsecure])

	// Neutral state: spread across hashing, HMAC, other
	e[HStateNeutral] = uniformEmission()
	e[HStateNeutral][APICallSHA256] = 0.15
	e[HStateNeutral][APICallSHA512] = 0.10
	e[HStateNeutral][APICallSHA3] = 0.10
	e[HStateNeutral][APICallHMAC] = 0.15
	e[HStateNeutral][APICallOther] = 0.10
	normalizeRow(&e[HStateNeutral])

	return e
}

// buildSecureEmission constructs emission probabilities for the secure model.
// Secure state (0) strongly emits MLKEM, MLDSA, AES-GCM calls.
func buildSecureEmission() [NumHiddenStates][NumAPICallTypes]float64 {
	var e [NumHiddenStates][NumAPICallTypes]float64

	// Secure state: high emission for post-quantum and authenticated encryption
	// Unauthenticated modes (CFB, CBC) have very low emission here.
	e[HStateSecure] = uniformEmission()
	e[HStateSecure][APICallMLKEMEncapsulate] = 0.20
	e[HStateSecure][APICallMLDSASign] = 0.15
	e[HStateSecure][APICallMLDSAVerify] = 0.12
	e[HStateSecure][APICallAESGCM] = 0.18
	e[HStateSecure][APICallAESNewCipher] = 0.08
	e[HStateSecure][APICallSHA3] = 0.08
	e[HStateSecure][APICallAESCBC] = 0.01
	e[HStateSecure][APICallAESCFB] = 0.01
	normalizeRow(&e[HStateSecure])

	// Insecure state: classical crypto calls and unauthenticated modes
	e[HStateInsecure] = uniformEmission()
	e[HStateInsecure][APICallRSAGenerateKey] = 0.10
	e[HStateInsecure][APICallRSAEncrypt] = 0.08
	e[HStateInsecure][APICallECDSASign] = 0.06
	e[HStateInsecure][APICallECDHSharedKey] = 0.06
	e[HStateInsecure][APICallAESNewCipher] = 0.10
	e[HStateInsecure][APICallAESCBC] = 0.12
	e[HStateInsecure][APICallAESCFB] = 0.12
	normalizeRow(&e[HStateInsecure])

	// Neutral state: hashing and utility
	e[HStateNeutral] = uniformEmission()
	e[HStateNeutral][APICallSHA256] = 0.15
	e[HStateNeutral][APICallSHA512] = 0.10
	e[HStateNeutral][APICallHMAC] = 0.15
	e[HStateNeutral][APICallOther] = 0.15
	normalizeRow(&e[HStateNeutral])

	return e
}

// uniformEmission returns a baseline emission row with uniform small probabilities.
func uniformEmission() [NumAPICallTypes]float64 {
	var row [NumAPICallTypes]float64
	base := 1.0 / float64(NumAPICallTypes)
	for i := range row {
		row[i] = base
	}
	return row
}

// normalizeRow normalizes a probability row so it sums to 1.
func normalizeRow(row *[NumAPICallTypes]float64) {
	var sum float64
	for _, v := range row {
		sum += v
	}
	if sum == 0 {
		return
	}
	for i := range row {
		row[i] /= sum
	}
}

// apiCallPatterns maps regex patterns to API call type constants.
var apiCallPatterns = []struct {
	pattern *regexp.Regexp
	apiCall int
}{
	{regexp.MustCompile(`rsa\.GenerateKey`), APICallRSAGenerateKey},
	{regexp.MustCompile(`rsa\.EncryptPKCS1v15|rsa\.EncryptOAEP`), APICallRSAEncrypt},
	{regexp.MustCompile(`rsa\.DecryptPKCS1v15|rsa\.DecryptOAEP`), APICallRSADecrypt},
	{regexp.MustCompile(`rsa\.SignPKCS1v15|rsa\.SignPSS`), APICallRSASign},
	{regexp.MustCompile(`ecdsa\.GenerateKey`), APICallECDSAGenerateKey},
	{regexp.MustCompile(`ecdsa\.Sign`), APICallECDSASign},
	{regexp.MustCompile(`ecdsa\.Verify`), APICallECDSAVerify},
	{regexp.MustCompile(`ecdh\.GenerateKey|elliptic\.GenerateKey`), APICallECDHGenerateKey},
	{regexp.MustCompile(`ecdh\.ECDH|elliptic\.Marshal`), APICallECDHSharedKey},
	{regexp.MustCompile(`aes\.NewCipher`), APICallAESNewCipher},
	{regexp.MustCompile(`cipher\.NewGCM`), APICallAESGCM},
	{regexp.MustCompile(`cipher\.NewCBCEncrypter|cipher\.NewCBCDecrypter`), APICallAESCBC},
	{regexp.MustCompile(`cipher\.NewCFBEncrypter|cipher\.NewCFBDecrypter`), APICallAESCFB},
	{regexp.MustCompile(`cipher\.NewCTR`), APICallAESCTR},
	{regexp.MustCompile(`sha256\.New|sha256\.Sum256`), APICallSHA256},
	{regexp.MustCompile(`sha512\.New|sha512\.Sum512`), APICallSHA512},
	{regexp.MustCompile(`sha3\.New|sha3\.Sum256|sha3\.Sum512`), APICallSHA3},
	{regexp.MustCompile(`hmac\.New`), APICallHMAC},
	{regexp.MustCompile(`mlkem\.Encapsulate|mlkem\.Decapsulate|kem\.Encapsulate`), APICallMLKEMEncapsulate},
	{regexp.MustCompile(`mldsa\.Sign|dilithium\.Sign`), APICallMLDSASign},
	{regexp.MustCompile(`mldsa\.Verify|dilithium\.Verify`), APICallMLDSAVerify},
}

// ExtractAPICallSequence scans source code and extracts crypto API calls
// in the order they appear, returning an ObservedAPICall for each match.
func ExtractAPICallSequence(source, filePath string) []ObservedAPICall {
	lines := strings.Split(source, "\n")
	var calls []ObservedAPICall

	for lineIdx, line := range lines {
		for _, pat := range apiCallPatterns {
			locs := pat.pattern.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				calls = append(calls, ObservedAPICall{
					Name:        line[loc[0]:loc[1]],
					APICallType: pat.apiCall,
					Line:        lineIdx + 1,
					FilePath:    filePath,
				})
			}
		}
	}

	return calls
}

// DetectPatterns analyzes a sequence of API call observations using two HMMs
// (insecure vs secure) and returns vulnerability patterns where the insecure
// model is a significantly better fit (LLR > threshold).
func (pd *PatternDetector) DetectPatterns(apiCalls []ObservedAPICall, filePath string) ([]VulnerabilityPattern, error) {
	if len(apiCalls) == 0 {
		return nil, nil
	}

	// Build observation sequence
	observations := make([]int, len(apiCalls))
	for i, call := range apiCalls {
		observations[i] = call.APICallType
	}

	// Run Viterbi on both models
	insecureResult, err := Viterbi(pd.insecureModel, observations)
	if err != nil {
		return nil, fmt.Errorf("hmm: viterbi on insecure model: %w", err)
	}

	secureResult, err := Viterbi(pd.secureModel, observations)
	if err != nil {
		return nil, fmt.Errorf("hmm: viterbi on secure model: %w", err)
	}

	// Compute log-likelihood ratio: positive means insecure model fits better
	insecureLogProb, err := Forward(pd.insecureModel, observations)
	if err != nil {
		return nil, fmt.Errorf("hmm: forward on insecure model: %w", err)
	}
	secureLogProb, err := Forward(pd.secureModel, observations)
	if err != nil {
		return nil, fmt.Errorf("hmm: forward on secure model: %w", err)
	}

	llr := insecureLogProb - secureLogProb

	// If the insecure model is not significantly better, no vulnerabilities
	if llr < pd.threshold {
		return nil, nil
	}

	// Extract runs of insecure states from the insecure model's Viterbi path
	var patterns []VulnerabilityPattern
	_ = secureResult // used for comparison; insecure path drives extraction

	i := 0
	for i < len(insecureResult.States) {
		if insecureResult.States[i] == HStateInsecure {
			runStart := i
			for i < len(insecureResult.States) && insecureResult.States[i] == HStateInsecure {
				i++
			}
			runEnd := i

			// Collect API call types in this run
			runObs := make([]int, runEnd-runStart)
			for j := runStart; j < runEnd; j++ {
				runObs[j-runStart] = observations[j]
			}

			// Determine vulnerability type based on the API calls in the run
			vuln := classifyVulnerability(runObs, apiCalls, runStart, runEnd, filePath, llr)
			if vuln != nil {
				patterns = append(patterns, *vuln)
			}
		} else {
			i++
		}
	}

	// If we found insecure model better but no specific insecure runs,
	// report the whole sequence as a general pattern
	if len(patterns) == 0 {
		patterns = append(patterns, VulnerabilityPattern{
			Finding: models.Finding{
				RuleID:      "HMM-001",
				Severity:    models.SeverityMedium,
				Category:    models.CategoryAsymmetricEncryption,
				FilePath:    filePath,
				Algorithm:   "mixed",
				Description: "HMM analysis indicates insecure crypto usage pattern",
				RecommendedFix: "Review cryptographic API usage for quantum-safe alternatives",
				Confidence:  0.6,
			},
			LogLikelihoodRatio: llr,
			InsecureRunStart:   0,
			InsecureRunEnd:     len(observations),
			APICallTypes:       observations,
		})
	}

	return patterns, nil
}

// classifyVulnerability maps a run of insecure-state observations to a
// specific vulnerability type with appropriate severity and recommendation.
func classifyVulnerability(runObs []int, apiCalls []ObservedAPICall, start, end int, filePath string, llr float64) *VulnerabilityPattern {
	hasRSA := containsAny(runObs, APICallRSAGenerateKey, APICallRSAEncrypt, APICallRSADecrypt, APICallRSASign)
	hasECDSA := containsAny(runObs, APICallECDSAGenerateKey, APICallECDSASign, APICallECDSAVerify)
	hasECDH := containsAny(runObs, APICallECDHGenerateKey, APICallECDHSharedKey)
	hasAESNewCipher := containsAny(runObs, APICallAESNewCipher)
	hasAESCFB := containsAny(runObs, APICallAESCFB)
	hasAESCBC := containsAny(runObs, APICallAESCBC)
	hasAESGCM := containsAny(runObs, APICallAESGCM)
	hasHMAC := containsAny(runObs, APICallHMAC)
	hasWeakHash := containsAny(runObs, APICallSHA256) && !containsAny(runObs, APICallSHA3)
	hasMLKEM := containsAny(runObs, APICallMLKEMEncapsulate)

	lineStart := 0
	lineEnd := 0
	if start < len(apiCalls) {
		lineStart = apiCalls[start].Line
	}
	if end-1 < len(apiCalls) && end > 0 {
		lineEnd = apiCalls[end-1].Line
	}

	// Unauthenticated AES: AES cipher used with CFB or CBC but no GCM
	if hasAESNewCipher && (hasAESCFB || hasAESCBC) && !hasAESGCM {
		return &VulnerabilityPattern{
			Finding: models.Finding{
				RuleID:          "HMM-003",
				Severity:        models.SeverityHigh,
				Category:        models.CategorySymmetricEncryption,
				FilePath:        filePath,
				LineStart:       lineStart,
				LineEnd:         lineEnd,
				Algorithm:       "AES-CFB/CBC",
				Description:     "Unauthenticated AES mode detected (CFB/CBC without GCM); vulnerable to padding oracle and ciphertext manipulation",
				RecommendedFix:  "Use AES-GCM or another AEAD mode for authenticated encryption",
				ReplacementAlgo: "AES-256-GCM",
				Confidence:      0.85,
			},
			LogLikelihoodRatio: llr,
			InsecureRunStart:   start,
			InsecureRunEnd:     end,
			APICallTypes:       runObs,
		}
	}

	// Non-hybrid RSA: RSA without any post-quantum KEM
	if hasRSA && !hasMLKEM {
		return &VulnerabilityPattern{
			Finding: models.Finding{
				RuleID:          "HMM-002",
				Severity:        models.SeverityCritical,
				Category:        models.CategoryAsymmetricEncryption,
				QuantumThreat:   models.ThreatBrokenByShor,
				FilePath:        filePath,
				LineStart:       lineStart,
				LineEnd:         lineEnd,
				Algorithm:       "RSA",
				Description:     "Non-hybrid RSA usage detected without post-quantum KEM; vulnerable to Shor's algorithm",
				RecommendedFix:  "Implement hybrid RSA + ML-KEM key encapsulation",
				ReplacementAlgo: "ML-KEM-768 + RSA-OAEP (hybrid)",
				Confidence:      0.9,
			},
			LogLikelihoodRatio: llr,
			InsecureRunStart:   start,
			InsecureRunEnd:     end,
			APICallTypes:       runObs,
		}
	}

	// Non-hybrid ECDSA or ECDH
	if (hasECDSA || hasECDH) && !hasMLKEM {
		algo := "ECDSA"
		replacement := "ML-DSA-65 + ECDSA (hybrid)"
		if hasECDH {
			algo = "ECDH"
			replacement = "ML-KEM-768 + ECDH (hybrid)"
		}
		return &VulnerabilityPattern{
			Finding: models.Finding{
				RuleID:          "HMM-004",
				Severity:        models.SeverityHigh,
				Category:        models.CategoryKeyExchange,
				QuantumThreat:   models.ThreatBrokenByShor,
				FilePath:        filePath,
				LineStart:       lineStart,
				LineEnd:         lineEnd,
				Algorithm:       algo,
				Description:     fmt.Sprintf("Non-hybrid %s usage detected; vulnerable to quantum attack", algo),
				RecommendedFix:  fmt.Sprintf("Implement hybrid post-quantum + classical %s", algo),
				ReplacementAlgo: replacement,
				Confidence:      0.85,
			},
			LogLikelihoodRatio: llr,
			InsecureRunStart:   start,
			InsecureRunEnd:     end,
			APICallTypes:       runObs,
		}
	}

	// Weak hash in HMAC: SHA-256 with HMAC but no SHA-3
	if hasHMAC && hasWeakHash {
		return &VulnerabilityPattern{
			Finding: models.Finding{
				RuleID:          "HMM-005",
				Severity:        models.SeverityMedium,
				Category:        models.CategoryHashing,
				QuantumThreat:   models.ThreatWeakenedByGrover,
				FilePath:        filePath,
				LineStart:       lineStart,
				LineEnd:         lineEnd,
				Algorithm:       "HMAC-SHA256",
				Description:     "HMAC with SHA-256 detected; Grover's algorithm halves effective security",
				RecommendedFix:  "Consider HMAC-SHA3-256 or increase key size to 256 bits",
				ReplacementAlgo: "HMAC-SHA3-256",
				Confidence:      0.7,
			},
			LogLikelihoodRatio: llr,
			InsecureRunStart:   start,
			InsecureRunEnd:     end,
			APICallTypes:       runObs,
		}
	}

	return nil
}

// containsAny returns true if the slice contains any of the given values.
func containsAny(slice []int, vals ...int) bool {
	for _, v := range slice {
		for _, target := range vals {
			if v == target {
				return true
			}
		}
	}
	return false
}

// DetectInFile reads a source file and runs the full detection pipeline.
func (pd *PatternDetector) DetectInFile(filePath string) ([]VulnerabilityPattern, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("hmm: reading file %s: %w", filePath, err)
	}

	apiCalls := ExtractAPICallSequence(string(data), filePath)
	if len(apiCalls) == 0 {
		return nil, nil
	}

	return pd.DetectPatterns(apiCalls, filePath)
}
