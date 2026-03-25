package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"quantumshield/internal/reporter"
	"quantumshield/internal/scanner"
	"quantumshield/pkg/models"
)

type Config struct {
	TargetPath  string
	IntervalSec int
	WebhookURL  string
	Format      string
	CIMode      bool
}

type Monitor struct {
	config   Config
	scanner  *scanner.Scanner
	reporter *reporter.Reporter
	lastScan *models.ScanResult
	mu       sync.Mutex
	stats    MonitorStats
}

type MonitorStats struct {
	ScanCount      int       `json:"scan_count"`
	StartedAt      time.Time `json:"started_at"`
	LastScanAt     time.Time `json:"last_scan_at"`
	TotalFindings  int       `json:"total_findings"`
	NewFindings    int       `json:"new_findings"`
	FixedFindings  int       `json:"fixed_findings"`
}

func New(cfg Config) (*Monitor, error) {
	s, err := scanner.New()
	if err != nil {
		return nil, err
	}

	return &Monitor{
		config:   cfg,
		scanner:  s,
		reporter: reporter.New(cfg.Format),
		stats: MonitorStats{
			StartedAt: time.Now(),
		},
	}, nil
}

func (m *Monitor) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	interval := time.Duration(m.config.IntervalSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial scan
	fmt.Fprintf(os.Stderr, "  [%s] Running initial scan...\n", time.Now().Format("15:04:05"))
	if err := m.runScan(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "  Initial scan error: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			m.printSummary()
			return nil
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n  Shutting down monitor...\n")
			m.printSummary()
			return nil
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "  [%s] Scanning...\n", time.Now().Format("15:04:05"))
			if err := m.runScan(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "  Scan error: %v\n", err)
			}
		}
	}
}

func (m *Monitor) runScan(ctx context.Context) error {
	result, err := m.scanner.Scan(ctx, scanner.ScanOptions{
		TargetPath:  m.config.TargetPath,
		ScanConfigs: true,
	})
	if err != nil {
		return err
	}

	m.mu.Lock()
	prevScan := m.lastScan
	m.lastScan = result
	m.stats.ScanCount++
	m.stats.LastScanAt = time.Now()
	m.stats.TotalFindings = result.Summary.TotalFindings
	m.mu.Unlock()

	// Diff against previous scan
	diff := m.diffScans(prevScan, result)

	if diff.NewCount > 0 || diff.FixedCount > 0 {
		m.mu.Lock()
		m.stats.NewFindings += diff.NewCount
		m.stats.FixedFindings += diff.FixedCount
		m.mu.Unlock()

		fmt.Fprintf(os.Stderr, "  [%s] Changes detected: +%d new, -%d fixed (total: %d)\n",
			time.Now().Format("15:04:05"), diff.NewCount, diff.FixedCount, result.Summary.TotalFindings)

		// Print new findings
		if diff.NewCount > 0 {
			fmt.Fprintf(os.Stderr, "  New findings:\n")
			for _, f := range diff.New {
				fmt.Fprintf(os.Stderr, "    + [%s] %s at %s:%d\n", f.Severity.String(), f.Algorithm, f.FilePath, f.LineStart)
			}
		}

		// Print fixed findings
		if diff.FixedCount > 0 {
			fmt.Fprintf(os.Stderr, "  Fixed findings:\n")
			for _, f := range diff.Fixed {
				fmt.Fprintf(os.Stderr, "    - [%s] %s at %s:%d\n", f.Severity.String(), f.Algorithm, f.FilePath, f.LineStart)
			}
		}

		// Send webhook if configured
		if m.config.WebhookURL != "" && diff.NewCount > 0 {
			go m.sendWebhook(diff)
		}
	} else {
		fmt.Fprintf(os.Stderr, "  [%s] No changes (total: %d findings)\n",
			time.Now().Format("15:04:05"), result.Summary.TotalFindings)
	}

	return nil
}

type ScanDiff struct {
	New        []models.Finding `json:"new"`
	Fixed      []models.Finding `json:"fixed"`
	NewCount   int              `json:"new_count"`
	FixedCount int              `json:"fixed_count"`
}

func (m *Monitor) diffScans(prev, curr *models.ScanResult) ScanDiff {
	if prev == nil {
		return ScanDiff{
			New:      curr.Findings,
			NewCount: len(curr.Findings),
		}
	}

	prevMap := make(map[string]models.Finding)
	for _, f := range prev.Findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
		prevMap[key] = f
	}

	currMap := make(map[string]models.Finding)
	for _, f := range curr.Findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
		currMap[key] = f
	}

	var diff ScanDiff

	// New findings (in curr but not prev)
	for key, f := range currMap {
		if _, ok := prevMap[key]; !ok {
			diff.New = append(diff.New, f)
			diff.NewCount++
		}
	}

	// Fixed findings (in prev but not curr)
	for key, f := range prevMap {
		if _, ok := currMap[key]; !ok {
			diff.Fixed = append(diff.Fixed, f)
			diff.FixedCount++
		}
	}

	return diff
}

func (m *Monitor) sendWebhook(diff ScanDiff) {
	payload := map[string]interface{}{
		"tool":    "quantumshield",
		"event":   "new_findings",
		"summary": fmt.Sprintf("%d new quantum-vulnerable findings detected", diff.NewCount),
		"diff":    diff,
		"stats":   m.stats,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	resp, err := http.Post(m.config.WebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Webhook error: %v\n", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Fprintf(os.Stderr, "  Webhook sent successfully\n")
	} else {
		fmt.Fprintf(os.Stderr, "  Webhook returned status %d\n", resp.StatusCode)
	}
}

func (m *Monitor) printSummary() {
	m.mu.Lock()
	defer m.mu.Unlock()

	duration := time.Since(m.stats.StartedAt)
	fmt.Fprintf(os.Stderr, "\n  Monitor Summary\n")
	fmt.Fprintf(os.Stderr, "  Duration:       %s\n", duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "  Scans run:      %d\n", m.stats.ScanCount)
	fmt.Fprintf(os.Stderr, "  Total findings: %d\n", m.stats.TotalFindings)
	fmt.Fprintf(os.Stderr, "  New detected:   %d\n", m.stats.NewFindings)
	fmt.Fprintf(os.Stderr, "  Fixed:          %d\n\n", m.stats.FixedFindings)
}

// GetLastScan returns the most recent scan result (used by the API server)
func (m *Monitor) GetLastScan() *models.ScanResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastScan
}

// GetStats returns current monitor stats (used by the API server)
func (m *Monitor) GetStats() MonitorStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}
