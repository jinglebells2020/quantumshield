package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"quantumshield/internal/analyzer/certscanner"
	"quantumshield/internal/analyzer/depgraph"
	"quantumshield/internal/analyzer/goast"
	"quantumshield/internal/rules"
	"quantumshield/pkg/crypto"
	"quantumshield/pkg/models"
)

type Scanner struct {
	engine  *rules.Engine
	workers int
}

type ScanOptions struct {
	TargetPath       string
	Languages        []string
	ScanConfigs      bool
	ScanDependencies bool
	ScanCertificates bool
	ExcludePaths     []string
	CustomRulesPath  string
	MinSeverity      models.Severity
	MaxWorkers       int
}

func New() (*Scanner, error) {
	engine, err := rules.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to init rule engine: %w", err)
	}

	return &Scanner{
		engine:  engine,
		workers: 8,
	}, nil
}

func (s *Scanner) RuleCount() int {
	return s.engine.RuleCount()
}

func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (*models.ScanResult, error) {
	start := time.Now()

	result := &models.ScanResult{
		ID:        fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		Config: models.ScanConfig{
			TargetPath:       opts.TargetPath,
			Languages:        opts.Languages,
			ScanConfigs:      opts.ScanConfigs,
			ScanDependencies: opts.ScanDependencies,
			ScanCertificates: opts.ScanCertificates,
			ExcludePaths:     opts.ExcludePaths,
		},
		Status:    "running",
		StartedAt: start,
	}

	files, err := s.walkFiles(opts)
	if err != nil {
		return nil, fmt.Errorf("walking files: %w", err)
	}

	findingsCh := make(chan models.Finding, 1000)
	var wg sync.WaitGroup
	var filesScanned int64
	var linesScanned int64

	workers := s.workers
	if opts.MaxWorkers > 0 {
		workers = opts.MaxWorkers
	}

	fileCh := make(chan fileEntry, len(files))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range fileCh {
				findings, lines := s.scanFile(ctx, f)
				atomic.AddInt64(&filesScanned, 1)
				atomic.AddInt64(&linesScanned, int64(lines))
				for _, finding := range findings {
					finding.ScanID = result.ID
					findingsCh <- finding
				}
			}
		}()
	}

	go func() {
		for _, f := range files {
			fileCh <- f
		}
		close(fileCh)
	}()

	go func() {
		wg.Wait()
		close(findingsCh)
	}()

	var allFindings []models.Finding
	for f := range findingsCh {
		allFindings = append(allFindings, f)
	}

	// Phase 2: Go AST deep analysis (higher confidence than regex)
	goASTAnalyzer := goast.New()
	for _, f := range files {
		if f.language == "go" {
			content, err := os.ReadFile(f.path)
			if err != nil {
				continue
			}
			astFindings, _ := goASTAnalyzer.AnalyzeFile(f.path, content)
			for i := range astFindings {
				astFindings[i].ScanID = result.ID
			}
			allFindings = append(allFindings, astFindings...)
		}
	}

	// Phase 3: Certificate scanning
	if opts.ScanCertificates {
		cs := certscanner.NewCertScanner()
		certFindings, err := cs.ScanDirectory(opts.TargetPath)
		if err == nil {
			for i := range certFindings {
				certFindings[i].ScanID = result.ID
			}
			allFindings = append(allFindings, certFindings...)
		}
	}

	// Phase 4: Dependency analysis
	if opts.ScanDependencies {
		da := depgraph.NewDepAnalyzer()
		_, depFindings, err := da.Analyze(opts.TargetPath)
		if err == nil {
			for i := range depFindings {
				depFindings[i].ScanID = result.ID
			}
			allFindings = append(allFindings, depFindings...)
		}
	}

	// Deduplicate findings (prefer higher confidence)
	allFindings = deduplicateFindings(allFindings)

	result.Findings = allFindings
	result.Status = "completed"
	result.CompletedAt = time.Now()
	result.DurationMs = time.Since(start).Milliseconds()
	result.FilesScanned = int(filesScanned)
	result.LinesScanned = int(linesScanned)
	result.RulesEvaluated = s.engine.RuleCount()
	result.Summary = buildSummary(allFindings)

	return result, nil
}

// deduplicateFindings removes duplicate findings, keeping the one with higher confidence.
func deduplicateFindings(findings []models.Finding) []models.Finding {
	best := make(map[string]models.Finding)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s", f.FilePath, f.LineStart, f.RuleID)
		if existing, ok := best[key]; ok {
			if f.Confidence > existing.Confidence {
				best[key] = f
			}
		} else {
			best[key] = f
		}
	}
	result := make([]models.Finding, 0, len(best))
	for _, f := range best {
		result = append(result, f)
	}
	return result
}

type fileEntry struct {
	path     string
	language string
}

var languageExtensions = map[string]string{
	".go":    "go",
	".py":    "python",
	".js":    "javascript",
	".ts":    "javascript",
	".jsx":   "javascript",
	".tsx":   "javascript",
	".java":  "java",
	".conf":  "config",
	".cfg":   "config",
	".yaml":  "config",
	".yml":   "config",
	".toml":  "config",
	".ini":   "config",
}

var defaultExcludes = []string{
	"vendor", "node_modules", ".git", ".svn", "dist", "build",
	"__pycache__", ".tox", ".venv", "venv", "target",
}

func (s *Scanner) walkFiles(opts ScanOptions) ([]fileEntry, error) {
	var files []fileEntry
	excludes := append(defaultExcludes, opts.ExcludePaths...)

	err := filepath.Walk(opts.TargetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			for _, ex := range excludes {
				if base == ex {
					return filepath.SkipDir
				}
			}
			return nil
		}

		ext := filepath.Ext(path)
		lang, ok := languageExtensions[ext]
		if !ok {
			base := filepath.Base(path)
			if isConfigFile(base) {
				lang = "config"
			} else {
				return nil
			}
		}

		if len(opts.Languages) > 0 && lang != "config" {
			found := false
			for _, l := range opts.Languages {
				if l == lang {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}

		files = append(files, fileEntry{path: path, language: lang})
		return nil
	})

	return files, err
}

func isConfigFile(name string) bool {
	configFiles := []string{
		"nginx.conf", "sshd_config", "ssh_config", "apache.conf",
		"httpd.conf", "Dockerfile", "docker-compose.yml",
	}
	lower := strings.ToLower(name)
	for _, cf := range configFiles {
		if lower == cf || strings.Contains(lower, cf) {
			return true
		}
	}
	return false
}

func (s *Scanner) scanFile(ctx context.Context, f fileEntry) ([]models.Finding, int) {
	file, err := os.Open(f.path)
	if err != nil {
		return nil, 0
	}
	defer file.Close()

	var findings []models.Finding
	lineNum := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		matches := s.engine.MatchLine(f.language, line)
		for _, match := range matches {
			finding := models.Finding{
				ID:            fmt.Sprintf("f-%s-%d-%s", filepath.Base(f.path), lineNum, match.Rule.ID),
				RuleID:        match.Rule.ID,
				Severity:      match.Rule.SeverityLevel(),
				Category:      match.Rule.CategoryType(),
				QuantumThreat: match.Rule.ThreatLevel(),
				FilePath:      f.path,
				LineStart:     lineNum,
				LineEnd:       lineNum,
				CodeSnippet:   strings.TrimSpace(line),
				Algorithm:     match.Rule.Name,
				Language:      f.language,
				Description:   match.Pattern.Message,
				ReplacementAlgo: match.Rule.Replacement,
				MigrationEffort: inferEffort(match.Rule),
				Confidence:    0.85,
				ComplianceRefs: match.Rule.ComplianceRefs,
				CreatedAt:     time.Now(),
			}

			if mig, ok := crypto.GetMigration(finding.Algorithm); ok {
				finding.ReplacementAlgo = mig.To
				finding.MigrationEffort = mig.Effort
			}

			findings = append(findings, finding)
		}
	}

	return findings, lineNum
}

func inferEffort(r *rules.Rule) string {
	switch r.SeverityLevel() {
	case models.SeverityCritical:
		return "medium"
	case models.SeverityHigh:
		return "medium"
	default:
		return "low"
	}
}

func buildSummary(findings []models.Finding) models.ScanSummary {
	s := models.ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		ByLanguage:    make(map[string]int),
		ByThreatLevel: make(map[string]int),
	}

	for _, f := range findings {
		s.BySeverity[f.Severity.String()]++
		s.ByCategory[f.Category.String()]++
		s.ByLanguage[f.Language]++
		s.ByThreatLevel[f.QuantumThreat.String()]++
	}

	if s.TotalFindings == 0 {
		s.QuantumReadiness = 100
		s.RiskScore = 0
	} else {
		shor := s.ByThreatLevel["Shor"]
		grover := s.ByThreatLevel["Grover"]
		total := float64(s.TotalFindings)
		s.RiskScore = (float64(shor)*1.0 + float64(grover)*0.4) / total * 100
		if s.RiskScore > 100 {
			s.RiskScore = 100
		}
		s.QuantumReadiness = 100 - s.RiskScore
	}

	return s
}
