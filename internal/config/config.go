// Package config provides configuration management for the TLS expiry monitor.
// It handles parsing command-line flags and environment variables into a unified
// configuration structure used throughout the application.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AlertLevel defines the severity of certificate expiry alerts.
type AlertLevel int

const (
	// AlertLevelInfo indicates a certificate is healthy with plenty of time remaining.
	AlertLevelInfo AlertLevel = iota
	// AlertLevelWarning indicates a certificate will expire soon (within warning threshold).
	AlertLevelWarning
	// AlertLevelCritical indicates a certificate is about to expire (within critical threshold).
	AlertLevelCritical
	// AlertLevelExpired indicates a certificate has already expired.
	AlertLevelExpired
)

// String returns the human-readable name of the alert level.
func (a AlertLevel) String() string {
	switch a {
	case AlertLevelInfo:
		return "INFO"
	case AlertLevelWarning:
		return "WARNING"
	case AlertLevelCritical:
		return "CRITICAL"
	case AlertLevelExpired:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

// Color returns the ANSI color code for terminal output.
func (a AlertLevel) Color() string {
	switch a {
	case AlertLevelInfo:
		return "\033[32m" // Green
	case AlertLevelWarning:
		return "\033[33m" // Yellow
	case AlertLevelCritical:
		return "\033[31m" // Red
	case AlertLevelExpired:
		return "\033[35m" // Magenta
	default:
		return "\033[0m"
	}
}

// Config holds all configuration options for the monitor.
type Config struct {
	// Domains is the list of hostnames to check (hostname:port format).
	Domains []string
	// WarningDays is the threshold for warning alerts (certificates expiring within this many days).
	WarningDays int
	// CriticalDays is the threshold for critical alerts (certificates expiring within this many days).
	CriticalDays int
	// Timeout is the network timeout for TLS handshakes.
	Timeout time.Duration
	// JSONOutput enables JSON-formatted output instead of human-readable text.
	JSONOutput bool
	// QuietMode suppresses INFO-level output, showing only warnings and errors.
	QuietMode bool
	// IncludeIPs checks IP addresses in addition to domain names.
	IncludeIPs bool
	// CheckRevocation enables certificate revocation checking via OCSP/CRL.
	CheckRevocation bool
}

// DefaultConfig returns a configuration with sensible defaults.
// These defaults work well for most production monitoring scenarios.
func DefaultConfig() *Config {
	return &Config{
		Domains:         []string{},
		WarningDays:     30,  // Warn when certificate expires within 30 days
		CriticalDays:    7,   // Critical when certificate expires within 7 days
		Timeout:         10 * time.Second,
		JSONOutput:      false,
		QuietMode:       false,
		IncludeIPs:      false,
		CheckRevocation: false,
	}
}

// ParseDomains converts a comma-separated string into a slice of domain strings.
// Empty entries and whitespace are automatically filtered out.
func ParseDomains(domainsStr string) []string {
	if domainsStr == "" {
		return []string{}
	}

	parts := strings.Split(domainsStr, ",")
	domains := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			// Normalize domain: add :443 if no port specified
			if !strings.Contains(trimmed, ":") {
				trimmed = trimmed + ":443"
			}
			domains = append(domains, trimmed)
		}
	}

	return domains
}

// LoadFromEnv reads configuration from environment variables.
// This allows containerized deployments to configure the monitor without command-line flags.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if domains := os.Getenv("TLS_DOMAINS"); domains != "" {
		cfg.Domains = ParseDomains(domains)
	}

	if days := os.Getenv("TLS_WARNING_DAYS"); days != "" {
		if d, err := strconv.Atoi(days); err == nil && d > 0 {
			cfg.WarningDays = d
		}
	}

	if days := os.Getenv("TLS_CRITICAL_DAYS"); days != "" {
		if d, err := strconv.Atoi(days); err == nil && d > 0 {
			cfg.CriticalDays = d
		}
	}

	if timeout := os.Getenv("TLS_TIMEOUT"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil && t > 0 {
			cfg.Timeout = time.Duration(t) * time.Second
		}
	}

	cfg.JSONOutput = os.Getenv("TLS_JSON") == "true" || os.Getenv("TLS_JSON") == "1"
	cfg.QuietMode = os.Getenv("TLS_QUIET") == "true" || os.Getenv("TLS_QUIET") == "1"
	cfg.CheckRevocation = os.Getenv("TLS_CHECK_REVOCATION") == "true" || os.Getenv("TLS_CHECK_REVOCATION") == "1"

	return cfg
}

// Validate checks that the configuration is valid and returns an error if not.
// Validation ensures thresholds are logically consistent (critical < warning).
func (c *Config) Validate() error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("no domains specified - use -domains flag or TLS_DOMAINS environment variable")
	}

	if c.CriticalDays >= c.WarningDays {
		return fmt.Errorf("critical days (%d) must be less than warning days (%d)", c.CriticalDays, c.WarningDays)
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	if c.WarningDays <= 0 || c.CriticalDays <= 0 {
		return fmt.Errorf("warning and critical days must be positive")
	}

	return nil
}

// GetAlertLevel determines the alert level based on days until expiry.
func (c *Config) GetAlertLevel(daysUntilExpiry float64) AlertLevel {
	if daysUntilExpiry < 0 {
		return AlertLevelExpired
	}
	if daysUntilExpiry <= float64(c.CriticalDays) {
		return AlertLevelCritical
	}
	if daysUntilExpiry <= float64(c.WarningDays) {
		return AlertLevelWarning
	}
	return AlertLevelInfo
}
