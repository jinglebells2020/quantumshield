package gitlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"quantumshield/pkg/models"
)

// MRCommenter posts notes on GitLab merge requests.
type MRCommenter struct {
	token     string
	projectID string
	baseURL   string
}

// NewMRCommenter creates a GitLab MR commenter.
func NewMRCommenter(projectID string) *MRCommenter {
	baseURL := os.Getenv("GITLAB_URL")
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	return &MRCommenter{
		token:     os.Getenv("GITLAB_TOKEN"),
		projectID: projectID,
		baseURL:   baseURL,
	}
}

// PostNote posts a summary note on a merge request.
func (mc *MRCommenter) PostNote(mrIID int, findings []models.Finding) error {
	if mc.token == "" {
		return fmt.Errorf("GITLAB_TOKEN not set")
	}

	body := FormatMRNote(findings)
	payload := map[string]string{"body": body}
	data, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%d/notes", mc.baseURL, mc.projectID, mrIID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", mc.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("GitLab API error: %d", resp.StatusCode)
	}
	return nil
}

// FormatMRNote formats findings as a GitLab markdown note.
func FormatMRNote(findings []models.Finding) string {
	if len(findings) == 0 {
		return "**QuantumShield**: No quantum-vulnerable cryptography detected. :white_check_mark:"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## :warning: QuantumShield: %d quantum-vulnerable findings\n\n", len(findings)))
	sb.WriteString("| Severity | Algorithm | Location | Replacement |\n")
	sb.WriteString("|----------|-----------|----------|-------------|\n")
	for _, f := range findings {
		sevLabels := []string{"Critical", "High", "Medium", "Low"}
		sev := "Unknown"
		if int(f.Severity) < len(sevLabels) {
			sev = sevLabels[f.Severity]
		}
		loc := fmt.Sprintf("`%s:%d`", f.FilePath, f.LineStart)
		repl := f.ReplacementAlgo
		if repl == "" {
			repl = "\u2014"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", sev, f.Algorithm, loc, repl))
		if len(sb.String()) > 50000 { // GitLab note size limit
			sb.WriteString(fmt.Sprintf("\n*...and %d more findings*\n", len(findings)))
			break
		}
	}
	return sb.String()
}
