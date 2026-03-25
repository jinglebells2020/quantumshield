package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"quantumshield/internal/analyzer/githistory"
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

func printBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  QuantumShield v%s\n", version.Version)
	fmt.Fprintf(os.Stderr, "  Quantum-Safe Crypto Scanner\n\n")
}
