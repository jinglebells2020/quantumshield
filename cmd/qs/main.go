package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"quantumshield/internal/analyzer/githistory"
	"quantumshield/internal/cbom"
	"quantumshield/internal/compliance"
	"quantumshield/internal/integrations/cloud"
	"quantumshield/internal/monitor"
	"quantumshield/internal/reporter"
	"quantumshield/internal/scanner"
	"quantumshield/internal/server"
	"quantumshield/internal/tui"
	"quantumshield/pkg/version"
)

func main() {
	root := &cobra.Command{
		Use:   "qs",
		Short: "QuantumShield — quantum-safe cryptography scanner",
		Long:  "Discover, assess, and migrate quantum-vulnerable cryptography in your codebase",
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run()
		},
	}

	root.AddCommand(scanCmd())
	root.AddCommand(monitorCmd())
	root.AddCommand(serveCmd())
	root.AddCommand(installHookCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(cbomCmd())
	root.AddCommand(diffCmd())
	root.AddCommand(complianceCmd())
	root.AddCommand(cloudCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		format      string
		output      string
		languages   []string
		exclude     []string
		severity    string
		ci          bool
		ciThreshold int
		workers     int
		quiet       bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a codebase for quantum-vulnerable cryptography",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			if !quiet {
				printBanner()
			}

			s, err := scanner.New()
			if err != nil {
				return fmt.Errorf("init failed: %w", err)
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "  Scanning %s...\n", target)
			}

			result, err := s.Scan(cmd.Context(), scanner.ScanOptions{
				TargetPath:   target,
				Languages:    languages,
				ScanConfigs:  true,
				ExcludePaths: exclude,
				MaxWorkers:   workers,
			})
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			r := reporter.New(format)
			if output != "" {
				if err := r.WriteFile(result, output); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "  Report written to %s\n", output)
			} else {
				if err := r.Write(os.Stdout, result); err != nil {
					return err
				}
			}

			if ci && result.Summary.TotalFindings > ciThreshold {
				return fmt.Errorf("CI threshold exceeded: %d findings (threshold: %d)", result.Summary.TotalFindings, ciThreshold)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, sarif)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringSliceVar(&languages, "lang", nil, "Languages to scan")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "Paths to exclude")
	cmd.Flags().StringVar(&severity, "severity", "all", "Minimum severity")
	cmd.Flags().BoolVar(&ci, "ci", false, "CI mode: non-zero exit on findings")
	cmd.Flags().IntVar(&ciThreshold, "ci-threshold", 0, "Max findings before CI failure")
	cmd.Flags().IntVar(&workers, "workers", 0, "Parallel workers (0=auto)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")

	return cmd
}

func monitorCmd() *cobra.Command {
	var (
		interval int
		webhook  string
		format   string
		ci       bool
	)

	cmd := &cobra.Command{
		Use:   "monitor [path]",
		Short: "Continuously monitor a codebase for crypto changes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			printBanner()
			fmt.Fprintf(os.Stderr, "  Starting active monitor on %s (interval: %ds)\n\n", target, interval)

			mon, err := monitor.New(monitor.Config{
				TargetPath:  target,
				IntervalSec: interval,
				WebhookURL:  webhook,
				Format:      format,
				CIMode:      ci,
			})
			if err != nil {
				return err
			}

			return mon.Run(cmd.Context())
		},
	}

	cmd.Flags().IntVarP(&interval, "interval", "i", 30, "Scan interval in seconds")
	cmd.Flags().StringVarP(&webhook, "webhook", "w", "", "Webhook URL for alerts")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format")
	cmd.Flags().BoolVar(&ci, "ci", false, "CI mode")

	return cmd
}

func serveCmd() *cobra.Command {
	var (
		port     string
		watch    string
		interval int
		webhook  string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the API server with background monitoring",
		RunE: func(cmd *cobra.Command, args []string) error {
			if envPort := os.Getenv("PORT"); envPort != "" && port == "8080" {
				port = envPort
			}
			if envWatch := os.Getenv("QS_WATCH_PATH"); envWatch != "" && watch == "." {
				watch = envWatch
			}
			if envWebhook := os.Getenv("QS_WEBHOOK_URL"); envWebhook != "" && webhook == "" {
				webhook = envWebhook
			}
			return server.Run(server.Config{
				Port:        port,
				WatchPath:   watch,
				IntervalSec: interval,
				WebhookURL:  webhook,
			})
		},
	}

	cmd.Flags().StringVarP(&port, "port", "p", "8080", "Server port")
	cmd.Flags().StringVarP(&watch, "watch", "w", ".", "Path to monitor")
	cmd.Flags().IntVarP(&interval, "interval", "i", 60, "Monitor interval in seconds")
	cmd.Flags().StringVar(&webhook, "webhook", "", "Webhook URL for alerts")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("QuantumShield %s\n", version.FullVersion())
		},
	}
}

func installHookCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-hook",
		Short: "Install a git pre-commit hook for quantum-safe scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			hookScript := githistory.GeneratePreCommitHook()
			hookPath := ".git/hooks/pre-commit"
			if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
				return fmt.Errorf("failed to write hook: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  Pre-commit hook installed at %s\n", hookPath)
			return nil
		},
	}
}

func cbomCmd() *cobra.Command {
	var (
		format  string
		output  string
		project string
		version string
	)

	cmd := &cobra.Command{
		Use:   "cbom [path]",
		Short: "Generate a Cryptographic Bill of Materials (CycloneDX v1.6)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			if project == "" {
				project = filepath.Base(target)
			}

			s, err := scanner.New()
			if err != nil {
				return err
			}

			result, err := s.Scan(cmd.Context(), scanner.ScanOptions{
				TargetPath:       target,
				ScanConfigs:      true,
				ScanCertificates: true,
				ScanDependencies: true,
			})
			if err != nil {
				return err
			}

			gen := cbom.NewGenerator(project, version)
			bom := gen.Generate(result.Findings)

			var out []byte
			switch format {
			case "csv":
				out = []byte(gen.ToCSV(bom))
			default:
				out, err = gen.ToJSON(bom)
				if err != nil {
					return err
				}
			}

			if output != "" {
				return os.WriteFile(output, out, 0644)
			}
			fmt.Print(string(out))
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format (json, csv)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVar(&project, "project", "", "Project name")
	cmd.Flags().StringVar(&version, "version", "", "Project version")

	return cmd
}

func diffCmd() *cobra.Command {
	var baseRef string

	cmd := &cobra.Command{
		Use:   "diff [path]",
		Short: "Show new/fixed findings since last baseline scan",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			bs := scanner.NewBaselineStore(target)
			baseline, err := bs.Load()
			if err != nil {
				return err
			}
			if baseline == nil {
				fmt.Fprintln(os.Stderr, "No baseline found. Run 'qs scan --save-baseline' first.")
				return nil
			}

			s, err := scanner.New()
			if err != nil {
				return err
			}

			result, err := s.Scan(cmd.Context(), scanner.ScanOptions{
				TargetPath:  target,
				ScanConfigs: true,
			})
			if err != nil {
				return err
			}

			diff := scanner.ComputeDiff(baseline, result.Findings)
			fmt.Fprintf(os.Stderr, "\n  New findings:   +%d\n", diff.NewCount)
			fmt.Fprintf(os.Stderr, "  Fixed findings: -%d\n\n", diff.FixedCount)

			for _, f := range diff.NewFindings {
				fmt.Fprintf(os.Stderr, "  + [%s] %s at %s:%d\n", f.Severity.String(), f.Algorithm, f.FilePath, f.LineStart)
			}
			for _, f := range diff.FixedFindings {
				fmt.Fprintf(os.Stderr, "  - [%s] %s at %s:%d\n", f.Severity.String(), f.Algorithm, f.FilePath, f.LineStart)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baseRef, "base", "origin/main", "Git ref to compare against")
	return cmd
}

func complianceCmd() *cobra.Command {
	var framework, format, output string

	cmd := &cobra.Command{
		Use:   "compliance [path]",
		Short: "Generate compliance report (CNSA 2.0, NSM-10, EU PQC, PCI DSS)",
		Long: `Scan a codebase and generate a regulatory compliance report mapping
findings to one or more frameworks: CNSA 2.0, NSM-10, EU PQC, PCI DSS 4.0.

Use --framework to select a single framework, or omit it for all frameworks.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			printBanner()
			fmt.Fprintf(os.Stderr, "  Scanning %s for compliance assessment...\n\n", target)

			s, err := scanner.New()
			if err != nil {
				return fmt.Errorf("init failed: %w", err)
			}

			result, err := s.Scan(cmd.Context(), scanner.ScanOptions{
				TargetPath:       target,
				ScanConfigs:      true,
				ScanCertificates: true,
				ScanDependencies: true,
			})
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			var report interface{}
			if framework == "" || strings.EqualFold(framework, "all") {
				report = compliance.GenerateAll(result.Findings)
			} else {
				fw, err := compliance.ParseFramework(framework)
				if err != nil {
					return err
				}
				report = compliance.GenerateReport(result.Findings, fw)
			}

			switch format {
			case "json":
				data, err := compliance.ToJSON(report)
				if err != nil {
					return err
				}
				if output != "" {
					if err := os.WriteFile(output, data, 0644); err != nil {
						return err
					}
					fmt.Fprintf(os.Stderr, "  Report written to %s\n", output)
				} else {
					fmt.Println(string(data))
				}

			default: // "table"
				writeComplianceTable(os.Stdout, report)
				if output != "" {
					f, err := os.Create(output)
					if err != nil {
						return err
					}
					defer f.Close()
					// Write JSON alongside the table output
					data, _ := json.MarshalIndent(report, "", "  ")
					f.Write(data)
					fmt.Fprintf(os.Stderr, "\n  JSON report written to %s\n", output)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&framework, "framework", "F", "all", "Framework (cnsa2, nsm-10, eu-pqc, pci-dss, all)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")

	return cmd
}

func writeComplianceTable(w *os.File, report interface{}) {
	switch r := report.(type) {
	case *compliance.ComplianceReport:
		printComplianceReport(w, r)
	case *compliance.MultiReport:
		for i, cr := range r.Reports {
			if i > 0 {
				fmt.Fprintf(w, "\n")
			}
			printComplianceReport(w, &cr)
		}
	}
}

func printComplianceReport(w *os.File, r *compliance.ComplianceReport) {
	statusColor := "\033[91m" // red
	if r.OverallStatus == "compliant" {
		statusColor = "\033[92m" // green
	} else if r.OverallStatus == "partially-compliant" {
		statusColor = "\033[93m" // yellow
	}

	fmt.Fprintf(w, "  ══════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "  %s COMPLIANCE REPORT\n", strings.ToUpper(string(r.Framework)))
	fmt.Fprintf(w, "  ══════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "  Status: %s%s\033[0m  |  Compliance: %.0f%%  |  Blocking: %d\n\n",
		statusColor, strings.ToUpper(r.OverallStatus), r.CompliancePct, r.BlockingFindings)

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  ID\tSTATUS\tBLOCKING\tDEADLINE\tDESCRIPTION\n")
	fmt.Fprintf(tw, "  --\t------\t--------\t--------\t-----------\n")

	for _, req := range r.Requirements {
		status := colorStatus(req.Status)
		fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%s\n",
			req.ID, status, req.Findings,
			req.Deadline.Format("2006-01-02"),
			truncate(req.Description, 50),
		)
	}
	tw.Flush()

	// Actions needed
	hasActions := false
	for _, req := range r.Requirements {
		if req.Status != "compliant" && len(req.Actions) > 0 {
			if !hasActions {
				fmt.Fprintf(w, "\n  REQUIRED ACTIONS:\n")
				hasActions = true
			}
			fmt.Fprintf(w, "  [%s]\n", req.ID)
			for _, a := range req.Actions {
				fmt.Fprintf(w, "    - %s\n", a)
			}
		}
	}

	fmt.Fprintf(w, "\n  %s\n", r.Summary)
}

func colorStatus(s string) string {
	switch s {
	case "compliant":
		return "\033[92mPASS\033[0m"
	case "non-compliant":
		return "\033[91mFAIL\033[0m"
	case "in-progress":
		return "\033[93mWIP \033[0m"
	case "not-applicable":
		return "\033[90mN/A \033[0m"
	default:
		return s
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func cloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Audit cloud KMS keys for quantum vulnerability",
	}

	// Subcommands
	awsCmd := &cobra.Command{
		Use:   "aws",
		Short: "Audit AWS KMS keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			region, _ := cmd.Flags().GetString("region")
			result, err := cloud.AuditAWSKMS(region)
			if err != nil {
				return err
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}
	awsCmd.Flags().String("region", "us-east-1", "AWS region")

	gcpCmd := &cobra.Command{
		Use:   "gcp",
		Short: "Audit GCP Cloud KMS keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			project, _ := cmd.Flags().GetString("project")
			result, err := cloud.AuditGCPKMS(project)
			if err != nil {
				return err
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}
	gcpCmd.Flags().String("project", "", "GCP project ID")

	azureCmd := &cobra.Command{
		Use:   "azure",
		Short: "Audit Azure Key Vault keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			vault, _ := cmd.Flags().GetString("vault")
			result, err := cloud.AuditAzureKV(vault)
			if err != nil {
				return err
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}
	azureCmd.Flags().String("vault", "", "Azure Key Vault name")

	cmd.AddCommand(awsCmd, gcpCmd, azureCmd)
	return cmd
}

func printBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  QuantumShield v%s\n", version.Version)
	fmt.Fprintf(os.Stderr, "  Quantum-Safe Crypto Scanner\n\n")
}
