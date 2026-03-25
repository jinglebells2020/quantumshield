package githistory

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// cryptoPatterns matches common cryptographic identifiers in diff lines.
var cryptoPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brsa\b`),
	regexp.MustCompile(`(?i)\becdsa\b`),
	regexp.MustCompile(`(?i)\becdh\b`),
	regexp.MustCompile(`(?i)\bmd5\b`),
	regexp.MustCompile(`(?i)\bsha1\b`),
	regexp.MustCompile(`(?i)\bsha-1\b`),
	regexp.MustCompile(`(?i)\baes\b`),
	regexp.MustCompile(`(?i)\bdes\b`),
	regexp.MustCompile(`(?i)\brc4\b`),
	regexp.MustCompile(`(?i)\btls\.`),
	regexp.MustCompile(`(?i)crypto/`),
	regexp.MustCompile(`(?i)crypto\.`),
	regexp.MustCompile(`(?i)\bGenerateKey\b`),
	regexp.MustCompile(`(?i)\bNewCipher\b`),
	regexp.MustCompile(`(?i)\bhashlib\b`),
	regexp.MustCompile(`(?i)\bMessageDigest\b`),
	regexp.MustCompile(`(?i)\bKeyPairGenerator\b`),
}

// pqcPatterns matches post-quantum cryptography references.
var pqcPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bmlkem\b`),
	regexp.MustCompile(`(?i)\bml-kem\b`),
	regexp.MustCompile(`(?i)\bmldsa\b`),
	regexp.MustCompile(`(?i)\bml-dsa\b`),
	regexp.MustCompile(`(?i)\bdilithium\b`),
	regexp.MustCompile(`(?i)\bkyber`),
	regexp.MustCompile(`(?i)\bpost.quantum\b`),
	regexp.MustCompile(`(?i)\bpqc\b`),
}

// cryptoExtensions are file extensions that may contain crypto-relevant code.
var cryptoExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".java": true,
	".conf": true,
	".pem":  true,
	".crt":  true,
	".ts":   true,
	".rb":   true,
	".rs":   true,
	".c":    true,
	".cpp":  true,
	".h":    true,
	".yaml": true,
	".yml":  true,
	".toml": true,
}

// GitAnalyzer analyzes git history for crypto-related changes.
type GitAnalyzer struct {
	repoPath string
}

// NewGitAnalyzer creates an analyzer for the given repo.
func NewGitAnalyzer(repoPath string) *GitAnalyzer {
	return &GitAnalyzer{repoPath: repoPath}
}

// AnalyzeHistory returns crypto-related commits from the git history.
// Uses git log and git diff to find commits that changed crypto-relevant files.
func (ga *GitAnalyzer) AnalyzeHistory(ctx context.Context, maxCommits int) ([]models.CryptoCommit, error) {
	// Step 1: Get commit SHAs, authors, and dates.
	logOutput, err := ga.runGit(ctx, "log", "--format=%H|%an|%aI", "--diff-filter=ACMR", "-n", fmt.Sprintf("%d", maxCommits))
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	if strings.TrimSpace(logOutput) == "" {
		return nil, nil
	}

	var commits []models.CryptoCommit

	scanner := bufio.NewScanner(strings.NewReader(logOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}

		sha := parts[0]
		author := parts[1]
		timestamp, err := time.Parse(time.RFC3339, parts[2])
		if err != nil {
			timestamp = time.Time{}
		}

		// Step 2: Get changed files for this commit.
		changedFiles, err := ga.getChangedFiles(ctx, sha)
		if err != nil {
			continue
		}

		// Step 3: Filter to crypto-relevant extensions.
		cryptoFiles := filterCryptoFiles(changedFiles)
		if len(cryptoFiles) == 0 {
			continue
		}

		// Step 4: Get the actual diff for this commit.
		diffOutput, err := ga.getCommitDiff(ctx, sha)
		if err != nil {
			continue
		}

		// Step 5-6: Scan diff lines for crypto patterns.
		addedVulns, removedVulns, addedPQC := scanDiffForCrypto(diffOutput)

		// Step 7: Classify the commit.
		action := classifyCommit(addedVulns, removedVulns, addedPQC)
		if action == "no_crypto_change" {
			continue
		}

		commit := models.CryptoCommit{
			SHA:          sha,
			Author:       author,
			Timestamp:    timestamp,
			FilesChanged: cryptoFiles,
			CryptoAction: action,
		}

		commits = append(commits, commit)
	}

	return commits, nil
}

// runGit executes a git command in the repo directory and returns stdout.
func (ga *GitAnalyzer) runGit(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = ga.repoPath
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// getChangedFiles returns the list of files changed in a commit.
func (ga *GitAnalyzer) getChangedFiles(ctx context.Context, sha string) ([]string, error) {
	// For the first commit, there is no parent; handle that case.
	output, err := ga.runGit(ctx, "diff", sha+"^.."+sha, "--name-only")
	if err != nil {
		// Possibly the first commit, try diff-tree for root commits.
		output, err = ga.runGit(ctx, "diff-tree", "--no-commit-id", "-r", "--name-only", sha)
		if err != nil {
			return nil, err
		}
	}

	var files []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		f := strings.TrimSpace(scanner.Text())
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// getCommitDiff returns the full diff for a commit.
func (ga *GitAnalyzer) getCommitDiff(ctx context.Context, sha string) (string, error) {
	output, err := ga.runGit(ctx, "diff", sha+"^.."+sha)
	if err != nil {
		// Fallback for root commits.
		output, err = ga.runGit(ctx, "diff-tree", "-p", sha)
		if err != nil {
			return "", err
		}
	}
	return output, nil
}

// filterCryptoFiles keeps only files with crypto-relevant extensions.
func filterCryptoFiles(files []string) []string {
	var result []string
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if cryptoExtensions[ext] {
			result = append(result, f)
		}
	}
	return result
}

// scanDiffForCrypto scans a unified diff and returns whether added/removed
// lines contain vulnerable crypto patterns and whether added lines contain PQC patterns.
func scanDiffForCrypto(diff string) (addedVulns bool, removedVulns bool, addedPQC bool) {
	scanner := bufio.NewScanner(strings.NewReader(diff))
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
			continue
		}

		// Skip diff metadata lines.
		if strings.HasPrefix(line, "diff ") || strings.HasPrefix(line, "index ") ||
			strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") ||
			strings.HasPrefix(line, "@@") {
			continue
		}

		if strings.HasPrefix(line, "+") {
			content := line[1:]
			if matchesCryptoPattern(content) {
				addedVulns = true
			}
			if matchesPQCPattern(content) {
				addedPQC = true
			}
		} else if strings.HasPrefix(line, "-") {
			content := line[1:]
			if matchesCryptoPattern(content) {
				removedVulns = true
			}
		}
	}
	return
}

// matchesCryptoPattern checks if a line matches any vulnerable crypto pattern.
// Lines that match PQC patterns are excluded (they are not vulnerable).
func matchesCryptoPattern(line string) bool {
	// If the line references post-quantum crypto, it is not vulnerable.
	if matchesPQCPattern(line) {
		return false
	}
	for _, p := range cryptoPatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// matchesPQCPattern checks if a line matches any post-quantum crypto pattern.
func matchesPQCPattern(line string) bool {
	for _, p := range pqcPatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// classifyCommit determines the crypto action for a commit based on diff analysis.
func classifyCommit(addedVulns, removedVulns, addedPQC bool) string {
	switch {
	case addedPQC:
		return "introduces_safe"
	case removedVulns && !addedVulns:
		return "fixes_vuln"
	case addedVulns:
		return "introduces_vuln"
	default:
		return "no_crypto_change"
	}
}

// GeneratePreCommitHook returns a shell script for a pre-commit hook
// that scans staged files for quantum-vulnerable cryptography.
func GeneratePreCommitHook() string {
	return `#!/usr/bin/env bash
# QuantumShield Pre-Commit Hook
# Scans staged files for quantum-vulnerable cryptography before allowing commits.
#
# Install: cp this file to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -euo pipefail

echo "QuantumShield: scanning staged files for quantum-vulnerable crypto..."

# Get list of staged files (added, copied, modified, renamed)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
    echo "QuantumShield: no staged files to scan."
    exit 0
fi

# Run qs scan in CI mode with threshold 0 (fail on any finding)
if ! qs scan --ci --ci-threshold 0 $STAGED_FILES; then
    echo ""
    echo "QuantumShield: quantum-vulnerable cryptography detected in staged files."
    echo "Please review the findings above and fix them before committing."
    echo ""
    echo "To bypass this check (not recommended), use: git commit --no-verify"
    exit 1
fi

echo "QuantumShield: no quantum-vulnerable cryptography found. Commit allowed."
exit 0
`
}

// GenerateGitHubAction returns a GitHub Actions workflow YAML that runs
// QuantumShield on pull requests and uploads SARIF results.
func GenerateGitHubAction() string {
	return `name: QuantumShield Crypto Scan

on:
  pull_request:
    branches: [ main, master, develop ]
  push:
    branches: [ main, master ]

permissions:
  contents: read
  security-events: write

jobs:
  quantumshield-scan:
    name: Scan for Quantum-Vulnerable Cryptography
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install QuantumShield
        run: |
          curl -sSL https://get.quantumshield.dev | bash
          echo "$HOME/.quantumshield/bin" >> $GITHUB_PATH

      - name: Run QuantumShield scan
        run: |
          qs scan --ci --format sarif --output results.sarif .
        continue-on-error: true

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: quantumshield

      - name: Run QuantumShield scan (text report)
        run: |
          qs scan --ci --ci-threshold 0 .
`
}
