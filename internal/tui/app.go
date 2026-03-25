package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"quantumshield/internal/scanner"
	"quantumshield/pkg/crypto"
	"quantumshield/pkg/models"
	"quantumshield/pkg/version"
)

type view int

const (
	viewDashboard view = iota
	viewFindings
	viewMonitor
	viewHelp
)

type scanResultMsg struct {
	result *models.ScanResult
	err    error
}

type monitorTickMsg time.Time

type monitorResultMsg struct {
	result      *models.ScanResult
	newCount    int
	fixedCount  int
	newFindings []models.Finding
}

type Model struct {
	width    int
	height   int
	input    textinput.Model
	viewport viewport.Model

	activeView      view
	scanner         *scanner.Scanner
	lastResult      *models.ScanResult
	prevResult      *models.ScanResult
	scanning        bool
	scanPath        string
	monitoring      bool
	monitorPath     string
	monitorInterval time.Duration

	// history of commands
	history    []string
	historyIdx int

	// monitor stats
	scanCount     int
	newFindings   int
	fixedFindings int
	startedAt     time.Time
	lastScanAt    time.Time
	alerts        []string

	// status message (ephemeral)
	statusMsg  string
	statusTime time.Time

	ready bool
}

func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Type a command... (try 'help')"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 80
	ti.Prompt = "❯ "
	ti.PromptStyle = inputPromptStyle
	ti.TextStyle = lipgloss.NewStyle().Foreground(textColor)

	s, _ := scanner.New()

	return Model{
		input:           ti,
		scanner:         s,
		activeView:      viewDashboard,
		history:         []string{},
		historyIdx:      -1,
		alerts:          []string{},
		startedAt:       time.Now(),
		monitorInterval: 30 * time.Second,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tea.WindowSize())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerH := 4
		statusH := 3
		inputH := 3
		tabH := 2
		vpHeight := m.height - headerH - statusH - inputH - tabH
		if vpHeight < 3 {
			vpHeight = 3
		}

		if !m.ready {
			m.viewport = viewport.New(m.width-4, vpHeight)
			m.viewport.SetContent(m.renderViewContent())
			m.ready = true
		} else {
			m.viewport.Width = m.width - 4
			m.viewport.Height = vpHeight
		}

		m.input.Width = m.width - 8
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeView = (m.activeView + 1) % 4
			m.viewport.SetContent(m.renderViewContent())
			m.viewport.GotoTop()
			return m, nil
		case "shift+tab":
			m.activeView = (m.activeView + 3) % 4
			m.viewport.SetContent(m.renderViewContent())
			m.viewport.GotoTop()
			return m, nil
		case "enter":
			cmd := strings.TrimSpace(m.input.Value())
			if cmd != "" {
				m.history = append(m.history, cmd)
				m.historyIdx = len(m.history)
				m.input.SetValue("")
				return m.executeCommand(cmd)
			}
			return m, nil
		case "up":
			if m.input.Focused() && len(m.history) > 0 {
				if m.historyIdx > 0 {
					m.historyIdx--
					m.input.SetValue(m.history[m.historyIdx])
					m.input.CursorEnd()
				}
				return m, nil
			}
		case "down":
			if m.input.Focused() && len(m.history) > 0 {
				if m.historyIdx < len(m.history)-1 {
					m.historyIdx++
					m.input.SetValue(m.history[m.historyIdx])
					m.input.CursorEnd()
				} else {
					m.historyIdx = len(m.history)
					m.input.SetValue("")
				}
				return m, nil
			}
		case "ctrl+l":
			m.lastResult = nil
			m.alerts = nil
			m.viewport.SetContent(m.renderViewContent())
			return m, nil
		case "1":
			if !m.input.Focused() {
				m.activeView = viewDashboard
				m.viewport.SetContent(m.renderViewContent())
				m.viewport.GotoTop()
				return m, nil
			}
		case "2":
			if !m.input.Focused() {
				m.activeView = viewFindings
				m.viewport.SetContent(m.renderViewContent())
				m.viewport.GotoTop()
				return m, nil
			}
		case "3":
			if !m.input.Focused() {
				m.activeView = viewMonitor
				m.viewport.SetContent(m.renderViewContent())
				m.viewport.GotoTop()
				return m, nil
			}
		case "4", "?":
			if !m.input.Focused() {
				m.activeView = viewHelp
				m.viewport.SetContent(m.renderViewContent())
				m.viewport.GotoTop()
				return m, nil
			}
		}

	case scanResultMsg:
		m.scanning = false
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Scan error: %v", msg.err)
			m.statusTime = time.Now()
		} else {
			m.prevResult = m.lastResult
			m.lastResult = msg.result
			m.scanCount++
			m.lastScanAt = time.Now()
			m.statusMsg = fmt.Sprintf("Scan complete: %d findings in %dms", msg.result.Summary.TotalFindings, msg.result.DurationMs)
			m.statusTime = time.Now()
			if m.activeView == viewDashboard || m.activeView == viewFindings {
				m.viewport.SetContent(m.renderViewContent())
			}
		}
		return m, nil

	case monitorTickMsg:
		if !m.monitoring {
			return m, nil
		}
		return m, tea.Batch(
			m.doScan(m.monitorPath),
			m.scheduleMonitorTick(),
		)

	case monitorResultMsg:
		m.prevResult = m.lastResult
		m.lastResult = msg.result
		m.scanCount++
		m.lastScanAt = time.Now()

		if msg.newCount > 0 {
			m.newFindings += msg.newCount
			alert := fmt.Sprintf("[%s] +%d new findings detected", time.Now().Format("15:04:05"), msg.newCount)
			m.alerts = append(m.alerts, alert)
			if len(m.alerts) > 50 {
				m.alerts = m.alerts[len(m.alerts)-50:]
			}
		}
		if msg.fixedCount > 0 {
			m.fixedFindings += msg.fixedCount
			alert := fmt.Sprintf("[%s] -%d findings fixed", time.Now().Format("15:04:05"), msg.fixedCount)
			m.alerts = append(m.alerts, alert)
		}
		if msg.newCount == 0 && msg.fixedCount == 0 {
			alert := fmt.Sprintf("[%s] No changes (%d findings)", time.Now().Format("15:04:05"), msg.result.Summary.TotalFindings)
			m.alerts = append(m.alerts, alert)
		}

		m.viewport.SetContent(m.renderViewContent())
		return m, nil
	}

	// Update sub-components
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) executeCommand(cmd string) (tea.Model, tea.Cmd) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return m, nil
	}

	switch parts[0] {
	case "scan", "s":
		path := "."
		if len(parts) > 1 {
			path = parts[1]
		}
		m.scanning = true
		m.scanPath = path
		m.statusMsg = fmt.Sprintf("Scanning %s...", path)
		m.statusTime = time.Now()
		m.activeView = viewFindings
		m.viewport.SetContent(m.renderViewContent())
		return m, m.doScan(path)

	case "monitor", "mon", "m":
		path := "."
		if len(parts) > 1 {
			path = parts[1]
		}
		m.monitoring = true
		m.monitorPath = path
		m.activeView = viewMonitor
		m.alerts = append(m.alerts, fmt.Sprintf("[%s] Monitor started on %s (interval: %s)", time.Now().Format("15:04:05"), path, m.monitorInterval))
		m.statusMsg = fmt.Sprintf("Monitoring %s", path)
		m.statusTime = time.Now()
		m.viewport.SetContent(m.renderViewContent())
		return m, tea.Batch(
			m.doScan(path),
			m.scheduleMonitorTick(),
		)

	case "stop":
		m.monitoring = false
		m.alerts = append(m.alerts, fmt.Sprintf("[%s] Monitor stopped", time.Now().Format("15:04:05")))
		m.statusMsg = "Monitor stopped"
		m.statusTime = time.Now()
		m.viewport.SetContent(m.renderViewContent())
		return m, nil

	case "interval":
		if len(parts) > 1 {
			d, err := time.ParseDuration(parts[1])
			if err == nil {
				m.monitorInterval = d
				m.statusMsg = fmt.Sprintf("Monitor interval set to %s", d)
			} else {
				m.statusMsg = fmt.Sprintf("Invalid duration: %s (try 30s, 1m, 5m)", parts[1])
			}
			m.statusTime = time.Now()
		}
		return m, nil

	case "clear", "cls":
		m.alerts = nil
		m.lastResult = nil
		m.prevResult = nil
		m.viewport.SetContent(m.renderViewContent())
		return m, nil

	case "dashboard", "dash", "d":
		m.activeView = viewDashboard
		m.viewport.SetContent(m.renderViewContent())
		m.viewport.GotoTop()
		return m, nil

	case "findings", "f":
		m.activeView = viewFindings
		m.viewport.SetContent(m.renderViewContent())
		m.viewport.GotoTop()
		return m, nil

	case "help", "h", "?":
		m.activeView = viewHelp
		m.viewport.SetContent(m.renderViewContent())
		m.viewport.GotoTop()
		return m, nil

	case "quit", "exit", "q":
		return m, tea.Quit

	default:
		m.statusMsg = fmt.Sprintf("Unknown command: %s (type 'help' for commands)", parts[0])
		m.statusTime = time.Now()
		return m, nil
	}
}

func (m *Model) doScan(path string) tea.Cmd {
	return func() tea.Msg {
		result, err := m.scanner.Scan(context.Background(), scanner.ScanOptions{
			TargetPath:  path,
			ScanConfigs: true,
		})
		if err != nil {
			return scanResultMsg{nil, err}
		}

		if m.monitoring && m.prevResult != nil {
			diff := diffFindings(m.prevResult, result)
			return monitorResultMsg{
				result:      result,
				newCount:    diff.newCount,
				fixedCount:  diff.fixedCount,
				newFindings: diff.newFindings,
			}
		}

		return scanResultMsg{result, nil}
	}
}

type findingDiff struct {
	newCount    int
	fixedCount  int
	newFindings []models.Finding
}

func diffFindings(prev, curr *models.ScanResult) findingDiff {
	if prev == nil {
		return findingDiff{newCount: len(curr.Findings), newFindings: curr.Findings}
	}
	prevMap := make(map[string]bool)
	for _, f := range prev.Findings {
		prevMap[fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)] = true
	}
	currMap := make(map[string]bool)
	for _, f := range curr.Findings {
		currMap[fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)] = true
	}

	var d findingDiff
	for _, f := range curr.Findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
		if !prevMap[key] {
			d.newCount++
			d.newFindings = append(d.newFindings, f)
		}
	}
	for key := range prevMap {
		if !currMap[key] {
			d.fixedCount++
		}
	}
	return d
}

func (m *Model) scheduleMonitorTick() tea.Cmd {
	return tea.Tick(m.monitorInterval, func(t time.Time) tea.Msg {
		return monitorTickMsg(t)
	})
}

// View renders the full UI
func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing QuantumShield..."
	}

	var s strings.Builder

	// Header
	s.WriteString(m.renderHeader())
	s.WriteString("\n")

	// Tabs
	s.WriteString(m.renderTabs())
	s.WriteString("\n")

	// Viewport (main content)
	s.WriteString(viewportStyle.Render(m.viewport.View()))
	s.WriteString("\n")

	// Status bar
	s.WriteString(m.renderStatusBar())
	s.WriteString("\n")

	// Input
	s.WriteString(m.renderInput())

	return appStyle.Render(s.String())
}

func (m *Model) renderHeader() string {
	logo := logoStyle.Render("◆ QuantumShield")
	ver := versionStyle.Render(fmt.Sprintf("v%s", version.Version))

	right := ""
	if m.lastResult != nil {
		readiness := m.lastResult.Summary.QuantumReadiness
		var scoreStr string
		if readiness >= 70 {
			scoreStr = scoreHighStyle.Render(fmt.Sprintf("%.0f/100", readiness))
		} else if readiness >= 40 {
			scoreStr = scoreMedStyle.Render(fmt.Sprintf("%.0f/100", readiness))
		} else {
			scoreStr = scoreLowStyle.Render(fmt.Sprintf("%.0f/100", readiness))
		}
		right = fmt.Sprintf("Quantum Readiness: %s", scoreStr)
	}

	left := fmt.Sprintf("%s %s", logo, ver)

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 6
	if gap < 1 {
		gap = 1
	}

	return headerStyle.Width(m.width - 4).Render(
		left + strings.Repeat(" ", gap) + right,
	)
}

func (m *Model) renderTabs() string {
	tabs := []string{"Dashboard", "Findings", "Monitor", "Help"}
	var rendered []string

	for i, tab := range tabs {
		if view(i) == m.activeView {
			rendered = append(rendered, activeTabStyle.Render(tab))
		} else {
			rendered = append(rendered, inactiveTabStyle.Render(tab))
		}
	}

	return "  " + strings.Join(rendered, " ")
}

func (m *Model) renderViewContent() string {
	switch m.activeView {
	case viewDashboard:
		return m.renderDashboard()
	case viewFindings:
		return m.renderFindings()
	case viewMonitor:
		return m.renderMonitorView()
	case viewHelp:
		return m.renderHelp()
	default:
		return ""
	}
}

func (m *Model) renderDashboard() string {
	var s strings.Builder

	if m.lastResult == nil {
		s.WriteString(headingStyle.Render("Welcome to QuantumShield"))
		s.WriteString("\n\n")
		s.WriteString("  Quantum-safe cryptography scanner and migration platform.\n")
		s.WriteString("  Detect quantum-vulnerable crypto across your codebase.\n\n")
		s.WriteString(subheadingStyle.Render("  Quick Start"))
		s.WriteString("\n\n")
		s.WriteString(fmt.Sprintf("  %s  Scan a directory for vulnerable crypto\n", helpKeyStyle.Render("scan <path>")))
		s.WriteString(fmt.Sprintf("  %s  Start continuous monitoring\n", helpKeyStyle.Render("monitor <path>")))
		s.WriteString(fmt.Sprintf("  %s  Show available commands\n\n", helpKeyStyle.Render("help")))
		s.WriteString(mutedStyle("  Tip: press Tab to switch between views\n"))
		return s.String()
	}

	r := m.lastResult

	// Readiness Score
	s.WriteString(headingStyle.Render("Quantum Readiness"))
	s.WriteString("\n\n")
	readiness := r.Summary.QuantumReadiness
	bar := renderProgressBar(readiness, 30)
	var scoreLabel string
	if readiness >= 70 {
		scoreLabel = scoreHighStyle.Render(fmt.Sprintf("  %.0f/100", readiness))
	} else if readiness >= 40 {
		scoreLabel = scoreMedStyle.Render(fmt.Sprintf("  %.0f/100", readiness))
	} else {
		scoreLabel = scoreLowStyle.Render(fmt.Sprintf("  %.0f/100", readiness))
	}
	s.WriteString(fmt.Sprintf("  %s %s\n\n", bar, scoreLabel))

	// Summary stats
	s.WriteString(headingStyle.Render("Scan Summary"))
	s.WriteString("\n\n")
	s.WriteString(fmt.Sprintf("  Files Scanned:    %d\n", r.FilesScanned))
	s.WriteString(fmt.Sprintf("  Rules Evaluated:  %d\n", r.RulesEvaluated))
	s.WriteString(fmt.Sprintf("  Total Findings:   %d\n", r.Summary.TotalFindings))
	s.WriteString(fmt.Sprintf("  Scan Duration:    %dms\n\n", r.DurationMs))

	// By severity
	s.WriteString(headingStyle.Render("Findings by Severity"))
	s.WriteString("\n\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		count := r.Summary.BySeverity[sev]
		if count > 0 {
			label := severityStyle(sev).Render(fmt.Sprintf("  %-10s", sev))
			bar := ""
			for i := 0; i < count && i < 40; i++ {
				bar += "█"
			}
			s.WriteString(fmt.Sprintf("%s %s %d\n", label, severityStyle(sev).Render(bar), count))
		}
	}
	s.WriteString("\n")

	// By threat
	s.WriteString(headingStyle.Render("Quantum Threat Breakdown"))
	s.WriteString("\n\n")
	if c := r.Summary.ByThreatLevel["Shor"]; c > 0 {
		s.WriteString(fmt.Sprintf("  %s  %d findings (broken by Shor's algorithm)\n", criticalStyle.Render("Shor"), c))
	}
	if c := r.Summary.ByThreatLevel["Grover"]; c > 0 {
		s.WriteString(fmt.Sprintf("  %s  %d findings (weakened by Grover's algorithm)\n", mediumStyle.Render("Grover"), c))
	}
	s.WriteString("\n")

	// By language
	if len(r.Summary.ByLanguage) > 0 {
		s.WriteString(headingStyle.Render("Languages Detected"))
		s.WriteString("\n\n")
		for lang, count := range r.Summary.ByLanguage {
			s.WriteString(fmt.Sprintf("  %-14s %d findings\n", lang, count))
		}
	}

	return s.String()
}

func (m *Model) renderFindings() string {
	var s strings.Builder

	if m.scanning {
		s.WriteString("\n  Scanning " + m.scanPath + "...\n")
		return s.String()
	}

	if m.lastResult == nil {
		s.WriteString("\n  No scan results yet. Run: scan <path>\n")
		return s.String()
	}

	r := m.lastResult
	findings := make([]models.Finding, len(r.Findings))
	copy(findings, r.Findings)

	// Sort and dedup
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity
		}
		return findings[i].FilePath < findings[j].FilePath
	})
	seen := make(map[string]bool)
	var deduped []models.Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.LineStart)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	findings = deduped

	s.WriteString(headingStyle.Render(fmt.Sprintf("Findings (%d)", len(findings))))
	s.WriteString("\n\n")

	// Table header
	hdr := fmt.Sprintf("  %-10s %-26s %-38s %-8s %s", "SEVERITY", "ALGORITHM", "LOCATION", "THREAT", "REPLACEMENT")
	s.WriteString(subheadingStyle.Render(hdr))
	s.WriteString("\n")
	s.WriteString(separatorStyle.Render("  " + strings.Repeat("─", m.width-8)))
	s.WriteString("\n")

	for _, f := range findings {
		sev := severityStyle(f.Severity.String()).Render(fmt.Sprintf("%-10s", f.Severity.String()))
		algo := fmt.Sprintf("%-26s", truncate(f.Algorithm, 25))
		loc := fmt.Sprintf("%-38s", truncate(shortenPath(f.FilePath)+fmt.Sprintf(":%d", f.LineStart), 37))
		threat := fmt.Sprintf("%-8s", f.QuantumThreat.String())

		replacement := f.ReplacementAlgo
		if mig, ok := crypto.GetMigration(f.Algorithm); ok {
			replacement = mig.To
		}
		replacement = truncate(replacement, 25)

		s.WriteString(fmt.Sprintf("  %s %s %s %s %s\n", sev, algo, loc, threat, replacement))
	}

	return s.String()
}

func (m *Model) renderMonitorView() string {
	var s strings.Builder

	s.WriteString(headingStyle.Render("Active Monitor"))
	s.WriteString("\n\n")

	if m.monitoring {
		s.WriteString(fmt.Sprintf("  Status:    %s\n", statusActiveStyle.Render("● Active")))
		s.WriteString(fmt.Sprintf("  Path:      %s\n", m.monitorPath))
		s.WriteString(fmt.Sprintf("  Interval:  %s\n", m.monitorInterval))
	} else {
		s.WriteString(fmt.Sprintf("  Status:    %s\n", statusInactiveStyle.Render("○ Inactive")))
		s.WriteString("  Run 'monitor <path>' to start\n")
	}

	s.WriteString(fmt.Sprintf("  Scans:     %d\n", m.scanCount))
	if m.lastResult != nil {
		s.WriteString(fmt.Sprintf("  Findings:  %d\n", m.lastResult.Summary.TotalFindings))
	}
	s.WriteString(fmt.Sprintf("  New:       %s\n", alertNewStyle.Render(fmt.Sprintf("+%d", m.newFindings))))
	s.WriteString(fmt.Sprintf("  Fixed:     %s\n", alertFixedStyle.Render(fmt.Sprintf("-%d", m.fixedFindings))))
	s.WriteString("\n")

	// Alert log
	s.WriteString(headingStyle.Render("Activity Log"))
	s.WriteString("\n\n")

	if len(m.alerts) == 0 {
		s.WriteString(mutedStyle("  No activity yet\n"))
	} else {
		// Show most recent first
		for i := len(m.alerts) - 1; i >= 0 && i >= len(m.alerts)-30; i-- {
			alert := m.alerts[i]
			if strings.Contains(alert, "+") && strings.Contains(alert, "new") {
				s.WriteString("  " + alertNewStyle.Render(alert) + "\n")
			} else if strings.Contains(alert, "fixed") {
				s.WriteString("  " + alertFixedStyle.Render(alert) + "\n")
			} else {
				s.WriteString("  " + mutedStyle(alert) + "\n")
			}
		}
	}

	return s.String()
}

func (m *Model) renderHelp() string {
	var s strings.Builder

	s.WriteString(headingStyle.Render("Commands"))
	s.WriteString("\n\n")

	cmds := []struct{ key, desc string }{
		{"scan <path>", "Scan a directory for quantum-vulnerable crypto"},
		{"monitor <path>", "Start continuous monitoring with periodic rescans"},
		{"stop", "Stop active monitoring"},
		{"interval <dur>", "Set monitor interval (e.g. 30s, 1m, 5m)"},
		{"dashboard", "Switch to dashboard view"},
		{"findings", "Switch to findings view"},
		{"clear", "Clear scan results and alerts"},
		{"quit", "Exit QuantumShield"},
	}

	for _, c := range cmds {
		s.WriteString(fmt.Sprintf("  %s  %s\n", helpKeyStyle.Render(fmt.Sprintf("%-20s", c.key)), helpDescStyle.Render(c.desc)))
	}

	s.WriteString("\n")
	s.WriteString(headingStyle.Render("Keyboard Shortcuts"))
	s.WriteString("\n\n")

	keys := []struct{ key, desc string }{
		{"Tab / Shift+Tab", "Switch between views"},
		{"↑ / ↓", "Command history / scroll content"},
		{"Ctrl+L", "Clear results"},
		{"Ctrl+C", "Quit"},
		{"Enter", "Execute command"},
	}

	for _, k := range keys {
		s.WriteString(fmt.Sprintf("  %s  %s\n", helpKeyStyle.Render(fmt.Sprintf("%-20s", k.key)), helpDescStyle.Render(k.desc)))
	}

	s.WriteString("\n")
	s.WriteString(headingStyle.Render("What We Detect"))
	s.WriteString("\n\n")

	detects := []struct{ algo, threat, replacement string }{
		{"RSA (all sizes)", "Shor's algorithm", "ML-KEM / ML-DSA"},
		{"ECDSA / ECDH", "Shor's algorithm", "ML-DSA / ML-KEM"},
		{"DH key exchange", "Shor's algorithm", "ML-KEM-768"},
		{"AES-128", "Grover's algorithm", "AES-256"},
		{"3DES / RC4 / Blowfish", "Grover + classical", "AES-256-GCM"},
		{"MD5 / SHA-1", "Grover + collisions", "SHA-256 / SHA-3"},
		{"TLS (RSA/ECDHE)", "Shor's algorithm", "TLS 1.3 + PQ hybrid"},
		{"SSH (RSA/ECDSA)", "Shor's algorithm", "PQ-safe SSH keys"},
	}

	s.WriteString(fmt.Sprintf("  %-26s %-22s %s\n", subheadingStyle.Render("Algorithm"), subheadingStyle.Render("Quantum Threat"), subheadingStyle.Render("Replacement")))
	s.WriteString(separatorStyle.Render("  " + strings.Repeat("─", 70)))
	s.WriteString("\n")
	for _, d := range detects {
		s.WriteString(fmt.Sprintf("  %-26s %-22s %s\n", d.algo, d.threat, d.replacement))
	}

	s.WriteString("\n")
	s.WriteString(headingStyle.Render("Languages Supported"))
	s.WriteString("\n\n")
	s.WriteString("  Go • Python • JavaScript/TypeScript • Java\n")
	s.WriteString("  Config files: nginx, sshd, apache, Dockerfile, Kubernetes\n")

	return s.String()
}

func (m *Model) renderStatusBar() string {
	var parts []string

	if m.lastResult != nil {
		parts = append(parts, statusItemStyle.Render(fmt.Sprintf("Findings: %d", m.lastResult.Summary.TotalFindings)))
	}

	if m.monitoring {
		parts = append(parts, statusActiveStyle.Render("● Monitor: active"))
	} else {
		parts = append(parts, statusInactiveStyle.Render("○ Monitor: off"))
	}

	if m.scanCount > 0 {
		parts = append(parts, statusItemStyle.Render(fmt.Sprintf("Scans: %d", m.scanCount)))
	}

	if m.scanning {
		parts = append(parts, statusActiveStyle.Render("⟳ Scanning..."))
	}

	// Show ephemeral status message
	if m.statusMsg != "" && time.Since(m.statusTime) < 10*time.Second {
		parts = append(parts, statusItemStyle.Render(m.statusMsg))
	}

	return statusBarStyle.Width(m.width - 4).Render(strings.Join(parts, "  │  "))
}

func (m *Model) renderInput() string {
	return inputStyle.Width(m.width - 4).Render(m.input.View())
}

// Helpers

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func shortenPath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) > 3 {
		return strings.Join(parts[len(parts)-3:], "/")
	}
	return p
}

func mutedStyle(s string) string {
	return lipgloss.NewStyle().Foreground(mutedColor).Render(s)
}

func Run() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
