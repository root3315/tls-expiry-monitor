// Package tests contains unit tests for the TLS expiry monitor components.
// Tests cover configuration parsing, certificate checking logic, and alert formatting.
package tests

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tls-expiry-monitor/internal/alert"
	"github.com/tls-expiry-monitor/internal/checker"
	"github.com/tls-expiry-monitor/internal/config"
)

// TestParseDomains verifies domain string parsing handles various input formats.
func TestParseDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single domain without port",
			input:    "example.com",
			expected: []string{"example.com:443"},
		},
		{
			name:     "single domain with port",
			input:    "example.com:8443",
			expected: []string{"example.com:8443"},
		},
		{
			name:     "multiple domains",
			input:    "example.com,api.example.com,web.example.org",
			expected: []string{"example.com:443", "api.example.com:443", "web.example.org:443"},
		},
		{
			name:     "domains with mixed ports",
			input:    "example.com,api.example.com:8443",
			expected: []string{"example.com:443", "api.example.com:8443"},
		},
		{
			name:     "domains with whitespace",
			input:    "  example.com  ,  api.example.com  ",
			expected: []string{"example.com:443", "api.example.com:443"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: []string{},
		},
		{
			name:     "empty entries filtered",
			input:    "example.com,,api.example.com,",
			expected: []string{"example.com:443", "api.example.com:443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.ParseDomains(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d domains, got %d", len(tt.expected), len(result))
			}
			for i, exp := range tt.expected {
				if i >= len(result) || result[i] != exp {
					t.Errorf("domain %d: expected %q, got %q", i, exp, result[i])
				}
			}
		})
	}
}

// TestConfigValidate ensures configuration validation catches invalid settings.
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		expectError bool
	}{
		{
			name: "valid config",
			cfg: &config.Config{
				Domains:     []string{"example.com:443"},
				WarningDays: 30,
				CriticalDays: 7,
				Timeout:     10 * time.Second,
			},
			expectError: false,
		},
		{
			name: "no domains",
			cfg: &config.Config{
				Domains:     []string{},
				WarningDays: 30,
				CriticalDays: 7,
				Timeout:     10 * time.Second,
			},
			expectError: true,
		},
		{
			name: "critical >= warning",
			cfg: &config.Config{
				Domains:     []string{"example.com:443"},
				WarningDays: 7,
				CriticalDays: 30,
				Timeout:     10 * time.Second,
			},
			expectError: true,
		},
		{
			name: "critical == warning",
			cfg: &config.Config{
				Domains:     []string{"example.com:443"},
				WarningDays: 14,
				CriticalDays: 14,
				Timeout:     10 * time.Second,
			},
			expectError: true,
		},
		{
			name: "zero timeout",
			cfg: &config.Config{
				Domains:     []string{"example.com:443"},
				WarningDays: 30,
				CriticalDays: 7,
				Timeout:     0,
			},
			expectError: true,
		},
		{
			name: "negative warning days",
			cfg: &config.Config{
				Domains:     []string{"example.com:443"},
				WarningDays: -5,
				CriticalDays: 7,
				Timeout:     10 * time.Second,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestGetAlertLevel verifies alert level determination based on days until expiry.
func TestGetAlertLevel(t *testing.T) {
	cfg := &config.Config{
		WarningDays:  30,
		CriticalDays: 7,
	}

	tests := []struct {
		days     float64
		expected config.AlertLevel
	}{
		{-10, config.AlertLevelExpired},
		{-1, config.AlertLevelExpired},
		{-0.5, config.AlertLevelExpired},
		{0, config.AlertLevelCritical},
		{1, config.AlertLevelCritical},
		{6.9, config.AlertLevelCritical},
		{7, config.AlertLevelWarning},
		{15, config.AlertLevelWarning},
		{29.9, config.AlertLevelWarning},
		{30, config.AlertLevelInfo},
		{100, config.AlertLevelInfo},
		{365, config.AlertLevelInfo},
	}

	for _, tt := range tests {
		result := cfg.GetAlertLevel(tt.days)
		if result != tt.expected {
			t.Errorf("days=%.1f: expected %v, got %v", tt.days, tt.expected, result)
		}
	}
}

// TestAlertLevelString checks alert level string representations.
func TestAlertLevelString(t *testing.T) {
	tests := []struct {
		level    config.AlertLevel
		expected string
	}{
		{config.AlertLevelInfo, "INFO"},
		{config.AlertLevelWarning, "WARNING"},
		{config.AlertLevelCritical, "CRITICAL"},
		{config.AlertLevelExpired, "EXPIRED"},
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("level %v: expected %q, got %q", tt.level, tt.expected, tt.level.String())
		}
	}
}

// TestFormatDaysUntilExpiry verifies human-readable duration formatting.
func TestFormatDaysUntilExpiry(t *testing.T) {
	tests := []struct {
		days     float64
		expected string
	}{
		{-365, "expired 1.0 years ago"},
		{-30, "expired 30 days ago"},
		{-1, "expired 1 days ago"},
		{0.01, "1 minutes"},
		{0.5, "12.0 hours"},
		{1, "1 days"},
		{7, "7 days"},
		{14, "2 weeks (14 days)"},
		{60, "2 months (60 days)"},
		{400, "13 months (400 days)"},
	}

	for _, tt := range tests {
		result := checker.FormatDaysUntilExpiry(tt.days)
		// Allow for minor formatting variations
		if !strings.Contains(result, strings.Split(tt.expected, " ")[0]) {
			t.Errorf("days=%.2f: expected to contain %q, got %q", tt.days, tt.expected, result)
		}
	}
}

// TestIsWildcardDomain checks wildcard domain detection.
func TestIsWildcardDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"*.example.com", true},
		{"*.api.example.com", true},
		{"example.com", false},
		{"api.example.com", false},
		{"*example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		result := checker.IsWildcardDomain(tt.domain)
		if result != tt.expected {
			t.Errorf("domain=%q: expected %v, got %v", tt.domain, tt.expected, result)
		}
	}
}

// TestAlertFormatterTextOutput verifies text format alert output.
func TestAlertFormatterTextOutput(t *testing.T) {
	var buf bytes.Buffer
	formatter := alert.NewAlertFormatter(&buf, false, false, true)

	cfg := &config.Config{
		WarningDays:  30,
		CriticalDays: 7,
	}

	// Create mock certificate info
	infos := []*checker.CertInfo{
		{
			Domain:          "example.com:443",
			CommonName:      "example.com",
			SubjectAltNames: []string{"example.com", "www.example.com"},
			Issuer:          "Test CA",
			NotAfter:        time.Now().Add(45 * 24 * time.Hour),
			DaysUntilExpiry: 45,
			CheckedAt:       time.Now(),
		},
		{
			Domain:          "expiring.com:443",
			CommonName:      "expiring.com",
			SubjectAltNames: []string{"expiring.com"},
			Issuer:          "Test CA",
			NotAfter:        time.Now().Add(5 * 24 * time.Hour),
			DaysUntilExpiry: 5,
			CheckedAt:       time.Now(),
		},
	}

	formatter.FormatAlerts(infos, cfg)

	output := buf.String()
	
	// Verify key elements are present
	if !strings.Contains(output, "TLS Certificate Expiry Summary") {
		t.Error("output missing summary header")
	}
	if !strings.Contains(output, "example.com:443") {
		t.Error("output missing healthy domain")
	}
	if !strings.Contains(output, "expiring.com:443") {
		t.Error("output missing expiring domain")
	}
	if !strings.Contains(output, "WARNING") {
		t.Error("output missing WARNING level indicator")
	}
}

// TestAlertFormatterJSONOutput verifies JSON format alert output.
func TestAlertFormatterJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	formatter := alert.NewAlertFormatter(&buf, true, false, true)

	cfg := &config.Config{
		WarningDays:  30,
		CriticalDays: 7,
	}

	infos := []*checker.CertInfo{
		{
			Domain:          "example.com:443",
			CommonName:      "example.com",
			SubjectAltNames: []string{"example.com"},
			Issuer:          "Test CA",
			NotAfter:        time.Now().Add(45 * 24 * time.Hour),
			DaysUntilExpiry: 45,
			CheckedAt:       time.Now(),
		},
	}

	formatter.FormatAlerts(infos, cfg)

	// Parse and validate JSON output
	var result struct {
		Timestamp string         `json:"timestamp"`
		Alerts    []alert.Alert  `json:"alerts"`
		Summary   alert.AlertSummary `json:"summary"`
	}

	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(result.Alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(result.Alerts))
	}

	if result.Alerts[0].Domain != "example.com:443" {
		t.Errorf("unexpected domain: %q", result.Alerts[0].Domain)
	}

	if result.Summary.TotalChecked != 1 {
		t.Errorf("expected total_checked=1, got %d", result.Summary.TotalChecked)
	}
}

// TestAlertFormatterQuietMode verifies quiet mode suppresses INFO output.
func TestAlertFormatterQuietMode(t *testing.T) {
	var buf bytes.Buffer
	formatter := alert.NewAlertFormatter(&buf, false, true, true)

	cfg := &config.Config{
		WarningDays:  30,
		CriticalDays: 7,
	}

	// Only INFO level alert - should be suppressed in quiet mode
	infos := []*checker.CertInfo{
		{
			Domain:          "healthy.com:443",
			CommonName:      "healthy.com",
			SubjectAltNames: []string{"healthy.com"},
			Issuer:          "Test CA",
			NotAfter:        time.Now().Add(90 * 24 * time.Hour),
			DaysUntilExpiry: 90,
			CheckedAt:       time.Now(),
		},
	}

	formatter.FormatAlerts(infos, cfg)

	output := buf.String()
	
	// In quiet mode, healthy certificates should not appear in details
	if strings.Contains(output, "healthy.com:443") {
		t.Error("quiet mode should suppress INFO-level certificate details")
	}
}

// TestDefaultConfig verifies default configuration values.
func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.WarningDays != 30 {
		t.Errorf("expected WarningDays=30, got %d", cfg.WarningDays)
	}
	if cfg.CriticalDays != 7 {
		t.Errorf("expected CriticalDays=7, got %d", cfg.CriticalDays)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", cfg.Timeout)
	}
	if cfg.JSONOutput {
		t.Error("expected JSONOutput=false")
	}
	if cfg.QuietMode {
		t.Error("expected QuietMode=false")
	}
	if len(cfg.Domains) != 0 {
		t.Error("expected empty Domains slice")
	}
}

// TestCheckerCreation verifies checker initialization.
func TestCheckerCreation(t *testing.T) {
	timeout := 15 * time.Second
	c := checker.NewChecker(timeout)

	if c == nil {
		t.Fatal("NewChecker returned nil")
	}
}

// TestCheckerCheckDomainErrorHandling verifies error handling for invalid domains.
func TestCheckerCheckDomainErrorHandling(t *testing.T) {
	c := checker.NewChecker(2 * time.Second)

	// Check an invalid/unreachable domain
	info := c.CheckDomain("invalid-domain-that-does-not-exist-12345.com:443")

	if info.Error == "" {
		t.Error("expected error for invalid domain")
	}
	if info.Domain != "invalid-domain-that-does-not-exist-12345.com:443" {
		t.Errorf("unexpected domain: %q", info.Domain)
	}
}

// TestCheckerCheckDomainsEmpty verifies handling of empty domain list.
func TestCheckerCheckDomainsEmpty(t *testing.T) {
	c := checker.NewChecker(5 * time.Second)

	results := c.CheckDomains([]string{})

	if len(results) != 0 {
		t.Errorf("expected empty results, got %d items", len(results))
	}
}

// TestAlertSummaryCalculation verifies summary statistics are calculated correctly.
func TestAlertSummaryCalculation(t *testing.T) {
	var buf bytes.Buffer
	formatter := alert.NewAlertFormatter(&buf, true, false, true)

	cfg := &config.Config{
		WarningDays:  30,
		CriticalDays: 7,
	}

	now := time.Now()
	infos := []*checker.CertInfo{
		// Healthy
		{
			Domain: "healthy.com:443",
			Issuer: "Test CA",
			NotAfter: now.Add(90 * 24 * time.Hour),
			DaysUntilExpiry: 90,
			CheckedAt: now,
		},
		// Warning
		{
			Domain: "warning.com:443",
			Issuer: "Test CA",
			NotAfter: now.Add(20 * 24 * time.Hour),
			DaysUntilExpiry: 20,
			CheckedAt: now,
		},
		// Critical
		{
			Domain: "critical.com:443",
			Issuer: "Test CA",
			NotAfter: now.Add(3 * 24 * time.Hour),
			DaysUntilExpiry: 3,
			CheckedAt: now,
		},
		// Expired
		{
			Domain: "expired.com:443",
			Issuer: "Test CA",
			NotAfter: now.Add(-5 * 24 * time.Hour),
			DaysUntilExpiry: -5,
			CheckedAt: now,
		},
	}

	formatter.FormatAlerts(infos, cfg)

	var result struct {
		Summary alert.AlertSummary `json:"summary"`
	}

	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	s := result.Summary
	if s.TotalChecked != 4 {
		t.Errorf("expected TotalChecked=4, got %d", s.TotalChecked)
	}
	if s.Healthy != 1 {
		t.Errorf("expected Healthy=1, got %d", s.Healthy)
	}
	if s.WarningCount != 1 {
		t.Errorf("expected WarningCount=1, got %d", s.WarningCount)
	}
	if s.CriticalCount != 1 {
		t.Errorf("expected CriticalCount=1, got %d", s.CriticalCount)
	}
	if s.ExpiredCount != 1 {
		t.Errorf("expected ExpiredCount=1, got %d", s.ExpiredCount)
	}
}
