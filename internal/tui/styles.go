package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	primaryColor   = lipgloss.Color("#7C3AED") // purple
	secondaryColor = lipgloss.Color("#06B6D4") // cyan
	accentColor    = lipgloss.Color("#10B981") // green
	warningColor   = lipgloss.Color("#F59E0B") // amber
	dangerColor    = lipgloss.Color("#EF4444") // red
	mutedColor     = lipgloss.Color("#6B7280") // gray
	textColor      = lipgloss.Color("#E5E7EB") // light gray
	bgColor        = lipgloss.Color("#111827") // dark bg
	surfaceColor   = lipgloss.Color("#1F2937") // surface

	// App frame
	appStyle = lipgloss.NewStyle().
			Padding(0, 1)

	// Header
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1).
			MarginBottom(1)

	logoStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor)

	versionStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	// Status bar
	statusBarStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderTop(true).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1).
			MarginTop(1)

	statusItemStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	statusActiveStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	statusInactiveStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	// Input
	inputPromptStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	inputStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderTop(true).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)

	// Findings table
	criticalStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	highStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))

	lowStyle = lipgloss.NewStyle().
			Foreground(secondaryColor)

	// Content area
	viewportStyle = lipgloss.NewStyle().
			Padding(0, 1)

	// Dashboard widgets
	widgetStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(1, 2).
			MarginRight(1)

	widgetTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(secondaryColor).
			MarginBottom(1)

	// Score display
	scoreHighStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	scoreMedStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	scoreLowStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	// Help
	helpKeyStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	// Notifications / alerts
	alertNewStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	alertFixedStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	// Headings in content
	headingStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			MarginBottom(1)

	subheadingStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(secondaryColor)

	// Progress bar
	progressFullStyle = lipgloss.NewStyle().
			Foreground(accentColor)

	progressEmptyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#374151"))

	// Tab styles
	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(primaryColor).
			Padding(0, 2)

	inactiveTabStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Padding(0, 2)

	// Separator
	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#374151"))

	// Finding list highlight (cursor selection)
	findingHighlightStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#1E3A5F")).
				Foreground(textColor)

	// Detail view styles
	detailLabelStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(secondaryColor).
				Width(20)

	detailValueStyle = lipgloss.NewStyle().
				Foreground(textColor)

	// Diff styles
	diffAddStyle = lipgloss.NewStyle().
			Foreground(accentColor)

	diffDelStyle = lipgloss.NewStyle().
			Foreground(dangerColor)

	diffHeaderStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	// Code snippet display
	codeLineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9CA3AF"))

	codeHighlightLineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F9FAFB")).
				Background(lipgloss.Color("#7C3AED")).
				Bold(true)

	codeLineNumStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#4B5563")).
				Width(6).
				Align(lipgloss.Right)

	// Badge styles
	badgeCriticalStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(dangerColor).
				Bold(true).
				Padding(0, 1)

	badgeHighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(warningColor).
			Bold(true).
			Padding(0, 1)

	badgeMediumStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000000")).
				Background(lipgloss.Color("#F59E0B")).
				Padding(0, 1)

	badgeLowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(secondaryColor).
			Padding(0, 1)

	// Info box for detail view
	infoBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(1, 2).
			MarginTop(1).
			MarginBottom(1)
)

func severityBadge(sev string) string {
	switch sev {
	case "CRITICAL":
		return badgeCriticalStyle.Render(" CRITICAL ")
	case "HIGH":
		return badgeHighStyle.Render(" HIGH ")
	case "MEDIUM":
		return badgeMediumStyle.Render(" MEDIUM ")
	case "LOW":
		return badgeLowStyle.Render(" LOW ")
	default:
		return sev
	}
}

func severityStyle(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return criticalStyle
	case "HIGH":
		return highStyle
	case "MEDIUM":
		return mediumStyle
	case "LOW":
		return lowStyle
	default:
		return lipgloss.NewStyle()
	}
}

func renderProgressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += progressFullStyle.Render("█")
		} else {
			bar += progressEmptyStyle.Render("░")
		}
	}
	return bar
}
