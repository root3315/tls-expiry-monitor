// tls-expiry-monitor is a CLI tool for monitoring TLS certificate expiry dates.
// It checks certificates for specified domains and generates alerts based on
// configurable thresholds, supporting both human-readable and JSON output formats.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tls-expiry-monitor/internal/alert"
	"github.com/tls-expiry-monitor/internal/checker"
	"github.com/tls-expiry-monitor/internal/config"
)

const (
	appName    = "tls-expiry-monitor"
	appVersion = "1.0.0"
	exitOK     = 0
	exitWarn   = 1
	exitCrit   = 2
	exitError  = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes the main program logic and returns an appropriate exit code.
// Separating logic into run() allows for easier testing of the main package.
func run(args []string) int {
	// Load environment-based configuration first, then override with CLI flags
	cfg := config.LoadFromEnv()

	// Define command-line flags with descriptive help text
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)

	fs.Usage = func() {
		printUsage(fs)
	}

	// Core configuration flags
	domains := fs.String("domains", strings.Join(cfg.Domains, ","),
		"Comma-separated list of domains to check (hostname:port format)")
	warningDays := fs.Int("warning-days", cfg.WarningDays,
		"Days until expiry to trigger WARNING alerts")
	criticalDays := fs.Int("critical-days", cfg.CriticalDays,
		"Days until expiry to trigger CRITICAL alerts")
	timeout := fs.Duration("timeout", cfg.Timeout,
		"Network timeout for TLS handshakes")

	// Output format flags
	jsonOutput := fs.Bool("json", cfg.JSONOutput,
		"Output results in JSON format")
	quietMode := fs.Bool("quiet", cfg.QuietMode,
		"Suppress INFO-level output, show only warnings and errors")
	noColor := fs.Bool("no-color", false,
		"Disable colored output")
	checkRevocation := fs.Bool("check-revocation", cfg.CheckRevocation,
		"Check certificate revocation status via OCSP/CRL")
	version := fs.Bool("version", false,
		"Print version information and exit")

	// Parse flags, handling errors gracefully
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		return exitError
	}

	// Handle version flag early
	if *version {
		fmt.Printf("%s version %s\n", appName, appVersion)
		return exitOK
	}

	// Merge CLI flags into configuration
	cfg.Domains = config.ParseDomains(*domains)
	cfg.WarningDays = *warningDays
	cfg.CriticalDays = *criticalDays
	cfg.Timeout = *timeout
	cfg.JSONOutput = *jsonOutput
	cfg.QuietMode = *quietMode
	cfg.CheckRevocation = *checkRevocation

	// Validate configuration before proceeding
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		return exitError
	}

	// Execute the certificate checks
	return executeChecks(cfg, noColor)
}

// executeChecks performs the actual certificate checking and alerting.
func executeChecks(cfg *config.Config, noColor *bool) int {
	// Create checker with configured timeout and revocation checking
	tlsChecker := checker.NewCheckerWithRevocation(cfg.Timeout, cfg.CheckRevocation)

	// Perform concurrent certificate checks
	// Concurrent checking reduces total execution time for multiple domains
	results := tlsChecker.CheckDomains(cfg.Domains)

	// Create alert formatter and process results
	formatter := alert.NewAlertFormatter(os.Stdout, cfg.JSONOutput, cfg.QuietMode, *noColor)
	highestLevel := formatter.FormatAlerts(results, cfg)

	// Return exit code based on highest alert level encountered
	// This enables integration with monitoring systems and CI/CD pipelines
	switch highestLevel {
	case config.AlertLevelExpired:
		return exitCrit
	case config.AlertLevelCritical:
		return exitCrit
	case config.AlertLevelWarning:
		return exitWarn
	default:
		return exitOK
	}
}

// printUsage displays comprehensive help information for the CLI.
func printUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `%s v%s

A CLI tool to monitor TLS certificate expiry dates and send alerts.

USAGE:
    %s [OPTIONS] -domains <domain1,domain2,...>

OPTIONS:
`, appName, appVersion, appName)

	fs.PrintDefaults()

	fmt.Fprintf(os.Stderr, `
EXAMPLES:
    # Check single domain
    %s -domains example.com

    # Check multiple domains with custom thresholds
    %s -domains api.example.com,web.example.com -warning-days 45 -critical-days 14

    # JSON output for programmatic processing
    %s -domains example.com -json

    # Quiet mode for cron jobs (only shows problems)
    %s -domains example.com -quiet

    # Check certificate revocation status via OCSP/CRL
    %s -domains example.com -check-revocation

    # Using environment variables
    TLS_DOMAINS=example.com TLS_WARNING_DAYS=30 %s

EXIT CODES:
    0 - All certificates are healthy
    1 - Warning: certificates expiring within warning threshold
    2 - Critical: certificates expired or expiring within critical threshold
    3 - Configuration or runtime error

ENVIRONMENT VARIABLES:
    TLS_DOMAINS           Comma-separated list of domains to check
    TLS_WARNING_DAYS      Days until expiry for WARNING alerts (default: 30)
    TLS_CRITICAL_DAYS     Days until expiry for CRITICAL alerts (default: 7)
    TLS_TIMEOUT           Network timeout in seconds (default: 10)
    TLS_JSON              Enable JSON output (true/false)
    TLS_QUIET             Suppress INFO output (true/false)
    TLS_CHECK_REVOCATION  Enable revocation checking via OCSP/CRL (true/false)
    NO_COLOR              Disable colored terminal output

`, appName, appName, appName, appName, appName, appName)
}

// formatDuration returns a human-readable duration string.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
