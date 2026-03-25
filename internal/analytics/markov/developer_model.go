package markov

import (
	"sort"

	"quantumshield/pkg/models"
)

// NumActions is the number of possible developer commit actions.
const NumActions = 4

// Developer commit action classifications.
const (
	NoCryptoChange = iota
	IntroducesVuln
	IntroducesSafe
	FixesVuln
)

// actionStrings maps CryptoAction string values to action indices.
var actionStrings = map[string]int{
	"no_crypto_change": NoCryptoChange,
	"introduces_vuln":  IntroducesVuln,
	"introduces_safe":  IntroducesSafe,
	"fixes_vuln":       FixesVuln,
}

// DeveloperProfile captures a single developer's Markov-modeled behavior
// with respect to cryptographic code changes.
type DeveloperProfile struct {
	Author           string
	TotalCommits     int
	TransitionMatrix [NumActions][NumActions]float64
	ActionDist       [NumActions]float64
	RiskScore        float64
	MostLikelyNext   int
}

// ActionLabel returns a human-readable label for an action index.
func ActionLabel(action int) string {
	switch action {
	case NoCryptoChange:
		return "NoCryptoChange"
	case IntroducesVuln:
		return "IntroducesVuln"
	case IntroducesSafe:
		return "IntroducesSafe"
	case FixesVuln:
		return "FixesVuln"
	default:
		return "Unknown"
	}
}

// DeveloperModeler builds Markov-chain-based developer behavior profiles
// from commit history.
type DeveloperModeler struct {
	minCommits int
}

// NewDeveloperModeler creates a modeler with default settings (minCommits=10).
func NewDeveloperModeler() *DeveloperModeler {
	return &DeveloperModeler{
		minCommits: 10,
	}
}

// NewDeveloperModelerWithMinCommits creates a modeler with a custom minimum commit threshold.
func NewDeveloperModelerWithMinCommits(min int) *DeveloperModeler {
	return &DeveloperModeler{
		minCommits: min,
	}
}

// ClassifyCommit maps a CryptoCommit's CryptoAction string to an action index.
// Falls back to heuristic classification based on findings if the CryptoAction
// field is empty.
func ClassifyCommit(commit models.CryptoCommit) int {
	if action, ok := actionStrings[commit.CryptoAction]; ok {
		return action
	}

	// Heuristic fallback based on findings
	hasAdded := len(commit.FindingsAdded) > 0
	hasRemoved := len(commit.FindingsRemoved) > 0

	switch {
	case hasAdded && !hasRemoved:
		// Added new findings (vulnerabilities)
		return IntroducesVuln
	case hasRemoved && !hasAdded:
		// Removed findings (fixed vulnerabilities)
		return FixesVuln
	case hasAdded && hasRemoved:
		// Mixed: check if net-positive or net-negative
		if len(commit.FindingsRemoved) >= len(commit.FindingsAdded) {
			return FixesVuln
		}
		return IntroducesVuln
	default:
		return NoCryptoChange
	}
}

// BuildProfile constructs a DeveloperProfile from a sequence of commits
// by a single author. The commits should be in chronological order.
//
// The risk score is computed as: 100 * (P(IntroducesVuln) - P(FixesVuln) + 1) / 2
// This maps to [0, 100] where 50 is neutral, >50 is risky, <50 is beneficial.
func (m *DeveloperModeler) BuildProfile(author string, commits []models.CryptoCommit) *DeveloperProfile {
	profile := &DeveloperProfile{
		Author:       author,
		TotalCommits: len(commits),
	}

	if len(commits) < 2 {
		profile.RiskScore = 50.0 // neutral with insufficient data
		return profile
	}

	// Classify all commits
	actions := make([]int, len(commits))
	for i, c := range commits {
		actions[i] = ClassifyCommit(c)
	}

	// Count action frequencies
	var actionCounts [NumActions]float64
	for _, a := range actions {
		actionCounts[a]++
	}
	total := float64(len(actions))
	for i := 0; i < NumActions; i++ {
		profile.ActionDist[i] = actionCounts[i] / total
	}

	// Count transitions with Laplace smoothing
	const smoothing = 0.01
	var counts [NumActions][NumActions]float64
	for i := 0; i < NumActions; i++ {
		for j := 0; j < NumActions; j++ {
			counts[i][j] = smoothing
		}
	}
	for i := 1; i < len(actions); i++ {
		counts[actions[i-1]][actions[i]]++
	}

	// Normalize rows
	for i := 0; i < NumActions; i++ {
		rowSum := 0.0
		for j := 0; j < NumActions; j++ {
			rowSum += counts[i][j]
		}
		if rowSum > 0 {
			for j := 0; j < NumActions; j++ {
				profile.TransitionMatrix[i][j] = counts[i][j] / rowSum
			}
		}
	}

	// Risk score: 100 * (P(IntroducesVuln) - P(FixesVuln) + 1) / 2
	pIntro := profile.ActionDist[IntroducesVuln]
	pFix := profile.ActionDist[FixesVuln]
	profile.RiskScore = 100.0 * (pIntro - pFix + 1.0) / 2.0

	// Clamp to [0, 100]
	if profile.RiskScore < 0 {
		profile.RiskScore = 0
	}
	if profile.RiskScore > 100 {
		profile.RiskScore = 100
	}

	// Most likely next action based on last commit's action
	lastAction := actions[len(actions)-1]
	maxProb := 0.0
	bestAction := NoCryptoChange
	for j := 0; j < NumActions; j++ {
		if profile.TransitionMatrix[lastAction][j] > maxProb {
			maxProb = profile.TransitionMatrix[lastAction][j]
			bestAction = j
		}
	}
	profile.MostLikelyNext = bestAction

	return profile
}

// BuildAllProfiles groups commits by author, builds a profile for each
// author with at least minCommits commits, and returns them sorted by
// risk score in descending order (highest risk first).
func (m *DeveloperModeler) BuildAllProfiles(commits []models.CryptoCommit) []*DeveloperProfile {
	// Group commits by author, preserving chronological order
	byAuthor := make(map[string][]models.CryptoCommit)
	authorOrder := make([]string, 0)
	for _, c := range commits {
		if _, exists := byAuthor[c.Author]; !exists {
			authorOrder = append(authorOrder, c.Author)
		}
		byAuthor[c.Author] = append(byAuthor[c.Author], c)
	}

	// Build profiles for authors meeting the minimum commit threshold
	profiles := make([]*DeveloperProfile, 0)
	for _, author := range authorOrder {
		authorCommits := byAuthor[author]
		if len(authorCommits) < m.minCommits {
			continue
		}

		// Sort by timestamp
		sort.Slice(authorCommits, func(i, j int) bool {
			return authorCommits[i].Timestamp.Before(authorCommits[j].Timestamp)
		})

		profile := m.BuildProfile(author, authorCommits)
		profiles = append(profiles, profile)
	}

	// Sort by risk score descending
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].RiskScore > profiles[j].RiskScore
	})

	return profiles
}

// PredictNextAction predicts the most likely next action for a developer
// given their profile and their most recent action.
func PredictNextAction(profile *DeveloperProfile, lastAction int) (nextAction int, probability float64) {
	if lastAction < 0 || lastAction >= NumActions {
		return NoCryptoChange, 0
	}

	maxProb := 0.0
	best := NoCryptoChange
	for j := 0; j < NumActions; j++ {
		if profile.TransitionMatrix[lastAction][j] > maxProb {
			maxProb = profile.TransitionMatrix[lastAction][j]
			best = j
		}
	}

	return best, maxProb
}
