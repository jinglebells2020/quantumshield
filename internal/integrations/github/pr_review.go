package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"quantumshield/pkg/models"
)

// PRReviewer posts inline review comments on GitHub pull requests
// for quantum-vulnerable cryptography findings.
type PRReviewer struct {
	token  string
	owner  string
	repo   string
	client *http.Client
}

// NewPRReviewer creates a reviewer that reads GITHUB_TOKEN from the environment.
func NewPRReviewer(owner, repo string) *PRReviewer {
	return &PRReviewer{
		token:  os.Getenv("GITHUB_TOKEN"),
		owner:  owner,
		repo:   repo,
		client: &http.Client{},
	}
}

// ReviewComment is one inline comment attached to a diff.
type ReviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Body string `json:"body"`
}

// ReviewRequest is the payload sent to the GitHub PR review endpoint.
type ReviewRequest struct {
	Body     string          `json:"body"`
	Event    string          `json:"event"`
	Comments []ReviewComment `json:"comments"`
}

// CheckRunOutput represents the output of a GitHub Check Run.
type CheckRunOutput struct {
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Text        string            `json:"text,omitempty"`
	Annotations []CheckAnnotation `json:"annotations,omitempty"`
}

// CheckAnnotation maps a finding to a GitHub check annotation.
type CheckAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
	Title           string `json:"title"`
}

// CheckRunRequest is the payload for creating a GitHub Check Run.
type CheckRunRequest struct {
	Name       string       `json:"name"`
	HeadSHA    string       `json:"head_sha"`
	Status     string       `json:"status"`
	Conclusion string       `json:"conclusion"`
	Output     CheckRunOutput `json:"output"`
}

// PostReview submits a PR review with inline comments for every finding
// that touches one of the changed files.
func (pr *PRReviewer) PostReview(prNumber int, findings []models.Finding, changedFiles []string) error {
	if pr.token == "" {
		return fmt.Errorf("GITHUB_TOKEN not set")
	}

	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var comments []ReviewComment
	for _, f := range findings {
		path := normalizeFilePath(f.FilePath)
		if !changedSet[path] {
			continue
		}
		comments = append(comments, ReviewComment{
			Path: path,
			Line: f.LineStart,
			Body: FormatFindingComment(f),
		})
	}

	if len(comments) == 0 {
		return nil // nothing to report
	}

	event := "COMMENT"
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			event = "REQUEST_CHANGES"
			break
		}
	}

	body := fmt.Sprintf(
		"## QuantumShield Scan Results\n\n"+
			"Found **%d** quantum-vulnerable cryptographic usage(s) in changed files.\n\n"+
			"| Metric | Value |\n"+
			"|--------|-------|\n"+
			"| Total Findings | %d |\n"+
			"| Files Affected | %d |\n\n"+
			"> Run `qs compliance` for a full regulatory compliance report.",
		len(comments), len(comments), countUniqueFiles(comments),
	)

	review := ReviewRequest{
		Body:     body,
		Event:    event,
		Comments: comments,
	}

	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/pulls/%d/reviews",
		pr.owner, pr.repo, prNumber,
	)

	payload, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("marshaling review: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pr.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := pr.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting review: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody bytes.Buffer
		errBody.ReadFrom(resp.Body)
		return fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, errBody.String())
	}

	return nil
}

// FormatFindingComment builds a rich markdown comment for a single finding.
func FormatFindingComment(f models.Finding) string {
	var b strings.Builder

	// Header
	b.WriteString("**:warning: QuantumShield: Quantum-vulnerable cryptography detected**\n\n")

	// Summary table
	b.WriteString("| Property | Value |\n")
	b.WriteString("|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| **Algorithm** | `%s` |\n", f.Algorithm))
	b.WriteString(fmt.Sprintf("| **Quantum Threat** | %s |\n", formatThreat(f.QuantumThreat)))
	b.WriteString(fmt.Sprintf("| **Severity** | %s |\n", formatSeverityBadge(f.Severity)))
	if f.ReplacementAlgo != "" {
		b.WriteString(fmt.Sprintf("| **Replacement** | `%s` |\n", f.ReplacementAlgo))
	}
	b.WriteString(fmt.Sprintf("| **CNSA 2.0 Deadline** | %s |\n", cnsaDeadline(f)))
	if f.MigrationEffort != "" {
		b.WriteString(fmt.Sprintf("| **Migration Effort** | %s |\n", f.MigrationEffort))
	}
	b.WriteString("\n")

	// Suggested fix (collapsible)
	if f.FixDiff != "" || f.ReplacementAlgo != "" {
		b.WriteString("<details>\n")
		b.WriteString("<summary><strong>Suggested Fix</strong></summary>\n\n")
		if f.FixDiff != "" {
			b.WriteString("```diff\n")
			b.WriteString(f.FixDiff)
			if !strings.HasSuffix(f.FixDiff, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		} else {
			b.WriteString(fmt.Sprintf(
				"Replace `%s` with `%s`. See the [CNSA 2.0 migration guide](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) for details.\n\n",
				f.Algorithm, f.ReplacementAlgo,
			))
		}
		b.WriteString("</details>\n\n")
	}

	// Dashboard link placeholder
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf(
		":link: [View in QuantumShield Dashboard](https://dashboard.quantumshield.dev/findings/%s)\n",
		f.ID,
	))

	return b.String()
}

// GenerateCheckRun produces a GitHub Check Run conclusion payload as JSON.
func (pr *PRReviewer) GenerateCheckRun(findings []models.Finding) (string, error) {
	conclusion := "success"
	title := "QuantumShield: No quantum-vulnerable cryptography found"

	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			critical++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			medium++
		case models.SeverityLow:
			low++
		}
	}

	if critical > 0 {
		conclusion = "failure"
		title = fmt.Sprintf("QuantumShield: %d critical quantum vulnerability findings", critical)
	} else if high > 0 {
		conclusion = "failure"
		title = fmt.Sprintf("QuantumShield: %d high-severity quantum vulnerability findings", high)
	} else if medium > 0 {
		conclusion = "neutral"
		title = fmt.Sprintf("QuantumShield: %d medium-severity findings", medium)
	} else if low > 0 {
		conclusion = "neutral"
		title = fmt.Sprintf("QuantumShield: %d low-severity findings", low)
	}

	summary := fmt.Sprintf(
		"Scanned for quantum-vulnerable cryptography.\n\n"+
			"| Severity | Count |\n"+
			"|----------|-------|\n"+
			"| Critical | %d |\n"+
			"| High | %d |\n"+
			"| Medium | %d |\n"+
			"| Low | %d |\n"+
			"| **Total** | **%d** |",
		critical, high, medium, low, len(findings),
	)

	var annotations []CheckAnnotation
	for _, f := range findings {
		annotations = append(annotations, CheckAnnotation{
			Path:            normalizeFilePath(f.FilePath),
			StartLine:       f.LineStart,
			EndLine:         f.LineEnd,
			AnnotationLevel: checkAnnotationLevel(f.Severity),
			Message:         fmt.Sprintf("%s: %s (replace with %s)", f.Algorithm, f.Description, f.ReplacementAlgo),
			Title:           fmt.Sprintf("Quantum-vulnerable: %s", f.Algorithm),
		})
	}

	checkRun := CheckRunRequest{
		Name:       "QuantumShield",
		Status:     "completed",
		Conclusion: conclusion,
		Output: CheckRunOutput{
			Title:       title,
			Summary:     summary,
			Annotations: annotations,
		},
	}

	data, err := json.MarshalIndent(checkRun, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling check run: %w", err)
	}
	return string(data), nil
}

// ---------- helpers ----------

func normalizeFilePath(p string) string {
	// Strip leading ./ or / for GitHub path matching.
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

func countUniqueFiles(comments []ReviewComment) int {
	seen := make(map[string]bool)
	for _, c := range comments {
		seen[c.Path] = true
	}
	return len(seen)
}

func formatThreat(t models.QuantumThreatLevel) string {
	switch t {
	case models.ThreatBrokenByShor:
		return ":red_circle: Broken by Shor's algorithm (exponential speedup)"
	case models.ThreatWeakenedByGrover:
		return ":orange_circle: Weakened by Grover's algorithm (quadratic speedup)"
	case models.ThreatNotDirectlyThreatened:
		return ":green_circle: Not directly threatened"
	default:
		return "Unknown"
	}
}

func formatSeverityBadge(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return ":red_square: CRITICAL"
	case models.SeverityHigh:
		return ":orange_square: HIGH"
	case models.SeverityMedium:
		return ":yellow_square: MEDIUM"
	case models.SeverityLow:
		return ":blue_square: LOW"
	default:
		return s.String()
	}
}

func cnsaDeadline(f models.Finding) string {
	switch f.Category {
	case models.CategoryKeyExchange, models.CategoryAsymmetricEncryption:
		return "2027 (ML-KEM required)"
	case models.CategoryDigitalSignature:
		return "2027 (ML-DSA/SLH-DSA required)"
	case models.CategoryHashing:
		return "2027 (SHA-384+ required)"
	case models.CategorySymmetricEncryption:
		return "2027 (AES-256 required)"
	case models.CategoryTLSCipherSuite:
		return "2027 (TLS 1.3 + PQ KE required)"
	case models.CategoryCertificate:
		return "2028 (PQ certificates for new CAs)"
	case models.CategorySSH:
		return "2029 (PQ SSH algorithms required)"
	default:
		return "2033 (full legacy deprecation)"
	}
}

func checkAnnotationLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "failure"
	case models.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}
