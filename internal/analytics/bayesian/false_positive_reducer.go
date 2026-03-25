package bayesian

import (
	"math"
	"sort"
	"strings"

	"quantumshield/pkg/models"
)

// ContextSignal represents a single contextual signal used in Bayesian inference.
type ContextSignal struct {
	Name              string  // human-readable signal name
	Observed          bool    // whether this signal was observed in the finding
	LikelihoodIfTrue  float64 // P(signal | true vulnerability)
	LikelihoodIfFalse float64 // P(signal | false positive)
}

// BayesianAssessment holds the result of a Bayesian false-positive assessment.
type BayesianAssessment struct {
	Finding          models.Finding  `json:"finding"`
	PriorProbability float64         `json:"prior_probability"`
	Posterior        float64         `json:"posterior"`
	Signals          []ContextSignal `json:"signals"`
	IsTruePositive   bool            `json:"is_true_positive"`
}

// BayesianOption configures a FalsePositiveReducer.
type BayesianOption func(*FalsePositiveReducer)

// WithDefaultPrior sets the default prior probability for a finding being a true
// vulnerability.
func WithDefaultPrior(p float64) BayesianOption {
	return func(r *FalsePositiveReducer) {
		r.defaultPrior = p
	}
}

// WithDecisionThreshold sets the threshold above which a finding is classified as
// a true positive.
func WithDecisionThreshold(t float64) BayesianOption {
	return func(r *FalsePositiveReducer) {
		r.decisionThreshold = t
	}
}

// WithRulePrior sets the prior probability for a specific rule ID.
func WithRulePrior(ruleID string, prior float64) BayesianOption {
	return func(r *FalsePositiveReducer) {
		r.rulePriors[ruleID] = prior
	}
}

// betaPrior tracks Beta distribution parameters for conjugate updates.
type betaPrior struct {
	alpha float64
	beta  float64
}

// FalsePositiveReducer uses Bayesian inference to reduce false positives in
// crypto findings by incorporating context signals.
type FalsePositiveReducer struct {
	defaultPrior      float64
	decisionThreshold float64
	rulePriors        map[string]float64
	signalDefaults    []ContextSignal
	betaPriors        map[string]*betaPrior // per-rule beta priors for online learning
}

// NewFalsePositiveReducer creates a new reducer with sensible defaults.
func NewFalsePositiveReducer(opts ...BayesianOption) *FalsePositiveReducer {
	r := &FalsePositiveReducer{
		defaultPrior:      0.70,
		decisionThreshold: 0.50,
		rulePriors:        make(map[string]float64),
		betaPriors:        make(map[string]*betaPrior),
		signalDefaults: []ContextSignal{
			{Name: "is_test_file", LikelihoodIfTrue: 0.15, LikelihoodIfFalse: 0.60},
			{Name: "in_comment", LikelihoodIfTrue: 0.02, LikelihoodIfFalse: 0.30},
			{Name: "variable_name_contains_test", LikelihoodIfTrue: 0.05, LikelihoodIfFalse: 0.40},
			{Name: "in_example_code", LikelihoodIfTrue: 0.10, LikelihoodIfFalse: 0.50},
			{Name: "in_deprecated_block", LikelihoodIfTrue: 0.30, LikelihoodIfFalse: 0.15},
			{Name: "high_severity_rule", LikelihoodIfTrue: 0.80, LikelihoodIfFalse: 0.40},
			{Name: "in_dependency", LikelihoodIfTrue: 0.85, LikelihoodIfFalse: 0.30},
			{Name: "called_in_production_path", LikelihoodIfTrue: 0.90, LikelihoodIfFalse: 0.20},
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ExtractSignals examines the finding and returns observed context signals
// based on file path, code snippet, severity, and other heuristics.
func (r *FalsePositiveReducer) ExtractSignals(f models.Finding) []ContextSignal {
	signals := make([]ContextSignal, len(r.signalDefaults))
	copy(signals, r.signalDefaults)

	lowerPath := strings.ToLower(f.FilePath)
	lowerSnippet := strings.ToLower(f.CodeSnippet)

	for i := range signals {
		switch signals[i].Name {
		case "is_test_file":
			signals[i].Observed = isTestFile(lowerPath)

		case "in_comment":
			signals[i].Observed = isComment(lowerSnippet)

		case "variable_name_contains_test":
			signals[i].Observed = containsTestVar(lowerSnippet)

		case "in_example_code":
			signals[i].Observed = isExampleCode(lowerPath)

		case "in_deprecated_block":
			signals[i].Observed = isDeprecated(lowerSnippet)

		case "high_severity_rule":
			signals[i].Observed = f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical

		case "in_dependency":
			signals[i].Observed = f.InDependency

		case "called_in_production_path":
			signals[i].Observed = isProductionPath(lowerPath)
		}
	}

	return signals
}

// isTestFile checks whether the file path indicates a test file.
func isTestFile(lowerPath string) bool {
	if strings.HasSuffix(lowerPath, "_test.go") {
		return true
	}
	if strings.HasSuffix(lowerPath, "_test.py") {
		return true
	}
	if strings.HasSuffix(lowerPath, ".test.js") || strings.HasSuffix(lowerPath, ".test.ts") {
		return true
	}
	if strings.HasSuffix(lowerPath, ".spec.js") || strings.HasSuffix(lowerPath, ".spec.ts") {
		return true
	}
	if strings.Contains(lowerPath, "/tests/") || strings.Contains(lowerPath, "/test/") {
		return true
	}
	if strings.Contains(lowerPath, "/spec/") {
		return true
	}
	return false
}

// isComment checks whether the snippet appears to be inside a comment.
func isComment(lowerSnippet string) bool {
	trimmed := strings.TrimSpace(lowerSnippet)
	if strings.HasPrefix(trimmed, "//") {
		return true
	}
	if strings.HasPrefix(trimmed, "#") {
		return true
	}
	if strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return true
	}
	return false
}

// containsTestVar checks for test/mock/fake/stub/example variable names.
func containsTestVar(lowerSnippet string) bool {
	markers := []string{"test", "mock", "fake", "stub", "example"}
	for _, m := range markers {
		if strings.Contains(lowerSnippet, m) {
			return true
		}
	}
	return false
}

// isExampleCode checks whether the file path is under an examples or demo directory.
func isExampleCode(lowerPath string) bool {
	if strings.Contains(lowerPath, "/examples/") || strings.Contains(lowerPath, "/example/") {
		return true
	}
	if strings.Contains(lowerPath, "/demo/") || strings.Contains(lowerPath, "/demos/") {
		return true
	}
	return false
}

// isDeprecated checks the snippet for deprecation markers.
func isDeprecated(lowerSnippet string) bool {
	if strings.Contains(lowerSnippet, "deprecated") {
		return true
	}
	if strings.Contains(lowerSnippet, "todo:remove") || strings.Contains(lowerSnippet, "todo: remove") {
		return true
	}
	return false
}

// isProductionPath returns true if the path does NOT look like test/example code.
func isProductionPath(lowerPath string) bool {
	if isTestFile(lowerPath) {
		return false
	}
	if isExampleCode(lowerPath) {
		return false
	}
	if strings.Contains(lowerPath, "/testdata/") || strings.Contains(lowerPath, "/fixtures/") {
		return false
	}
	if strings.Contains(lowerPath, "/vendor/") {
		return false
	}
	// If the path is non-empty and none of the exclusions matched, treat as production.
	return lowerPath != ""
}

// ComputePosterior calculates the posterior probability of a finding being a true
// vulnerability using Bayes' theorem in log-odds form for numerical stability.
//
// The log-odds form avoids multiplying many small probabilities:
//
//	log-odds(posterior) = log-odds(prior) + sum_i log(P(signal_i|H) / P(signal_i|~H))
//
// For unobserved signals the complement likelihoods are used.
func (r *FalsePositiveReducer) ComputePosterior(prior float64, signals []ContextSignal) float64 {
	lo := LogOdds(prior)

	for _, s := range signals {
		var lr float64
		if s.Observed {
			// Observed: update with P(observed|true) / P(observed|false)
			lr = logLikelihoodRatio(s.LikelihoodIfTrue, s.LikelihoodIfFalse)
		} else {
			// Not observed: update with P(not observed|true) / P(not observed|false)
			lr = logLikelihoodRatio(1-s.LikelihoodIfTrue, 1-s.LikelihoodIfFalse)
		}
		lo += lr
	}

	return FromLogOdds(lo)
}

// logLikelihoodRatio returns log(a/b) safely.
func logLikelihoodRatio(a, b float64) float64 {
	if b == 0 {
		if a == 0 {
			return 0
		}
		return math.Inf(1)
	}
	if a == 0 {
		return math.Inf(-1)
	}
	return math.Log(a / b)
}

// priorFor returns the prior probability for a given rule, falling back to the
// default prior if no rule-specific prior exists.
func (r *FalsePositiveReducer) priorFor(ruleID string) float64 {
	if p, ok := r.rulePriors[ruleID]; ok {
		return p
	}
	if bp, ok := r.betaPriors[ruleID]; ok {
		return BetaMean(bp.alpha, bp.beta)
	}
	return r.defaultPrior
}

// AssessFinding performs a full Bayesian assessment of a single finding.
func (r *FalsePositiveReducer) AssessFinding(f models.Finding) BayesianAssessment {
	prior := r.priorFor(f.RuleID)
	signals := r.ExtractSignals(f)
	posterior := r.ComputePosterior(prior, signals)

	return BayesianAssessment{
		Finding:          f,
		PriorProbability: prior,
		Posterior:        posterior,
		Signals:          signals,
		IsTruePositive:   posterior >= r.decisionThreshold,
	}
}

// AssessAll assesses every finding and returns assessments sorted by posterior
// probability in descending order (most likely true vulnerabilities first).
func (r *FalsePositiveReducer) AssessAll(findings []models.Finding) []BayesianAssessment {
	assessments := make([]BayesianAssessment, 0, len(findings))
	for _, f := range findings {
		assessments = append(assessments, r.AssessFinding(f))
	}

	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].Posterior > assessments[j].Posterior
	})

	return assessments
}

// UpdatePriors performs a conjugate Beta update for the given rule based on
// analyst feedback. isTruePositive=true means the finding was confirmed as a
// real vulnerability; false means it was a false positive.
func (r *FalsePositiveReducer) UpdatePriors(ruleID string, isTruePositive bool) {
	bp, ok := r.betaPriors[ruleID]
	if !ok {
		// Initialise from the current prior so the first update is smooth.
		currentPrior := r.defaultPrior
		if p, exists := r.rulePriors[ruleID]; exists {
			currentPrior = p
		}
		// Convert prior to pseudo-counts. Use a strength of 2 (weak prior).
		bp = &betaPrior{
			alpha: currentPrior * 2,
			beta:  (1 - currentPrior) * 2,
		}
		r.betaPriors[ruleID] = bp
	}

	bp.alpha, bp.beta = BetaUpdate(bp.alpha, bp.beta, isTruePositive)

	// Propagate the updated mean back into rulePriors for easy look-up.
	r.rulePriors[ruleID] = BetaMean(bp.alpha, bp.beta)
}

// GetFilteredFindings returns only the findings whose posterior probability
// meets or exceeds the decision threshold (i.e., likely true positives).
func (r *FalsePositiveReducer) GetFilteredFindings(findings []models.Finding) []models.Finding {
	assessments := r.AssessAll(findings)
	filtered := make([]models.Finding, 0, len(assessments))
	for _, a := range assessments {
		if a.IsTruePositive {
			filtered = append(filtered, a.Finding)
		}
	}
	return filtered
}
