// Package alert handles formatting and output of certificate expiry alerts.
// It supports multiple output formats (text, JSON) and colorized terminal output.
package alert

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tls-expiry-monitor/internal/checker"
	"github.com/tls-expiry-monitor/internal/config"
)

// Alert represents a single certificate alert with all relevant information.
type Alert struct {
	Level           config.AlertLevel `json:"level"`
	Domain          string            `json:"domain"`
	CommonName      string            `json:"common_name,omitempty"`
	SubjectAltNames []string          `json:"subject_alt_names,omitempty"`
	Issuer          string            `json:"issuer,omitempty"`
	ExpiryDate      time.Time         `json:"expiry_date"`
	DaysUntilExpiry float64           `json:"days_until_expiry"`
	SerialNumber    string            `json:"serial_number,omitempty"`
	Message         string            `json:"message"`
	CheckedAt       time.Time         `json:"checked_at"`
	Error           string            `json:"error,omitempty"`
}

// AlertSummary provides aggregate statistics about all checked certificates.
type AlertSummary struct {
	TotalChecked    int `json:"total_checked"`
	Healthy         int `json:"healthy"`
	WarningCount    int `json:"warning_count"`
	CriticalCount   int `json:"critical_count"`
	ExpiredCount    int `json:"expired_count"`
	ErrorCount      int `json:"error_count"`
	AverageDaysLeft float64 `json:"average_days_left,omitempty"`
}

// AlertFormatter handles formatting alerts for different output modes.
type AlertFormatter struct {
	writer    io.Writer
	jsonMode  bool
	quietMode bool
	noColor   bool
}

// NewAlertFormatter creates a new formatter writing to the specified destination.
func NewAlertFormatter(w io.Writer, jsonMode, quietMode, noColor bool) *AlertFormatter {
	return &AlertFormatter{
		writer:    w,
		jsonMode:  jsonMode,
		quietMode: quietMode,
		noColor:   noColor,
	}
}

// FormatAlerts processes certificate info and outputs formatted alerts.
// Returns the highest alert level encountered for exit code determination.
func (f *AlertFormatter) FormatAlerts(infos []*checker.CertInfo, cfg *config.Config) config.AlertLevel {
	alerts := make([]*Alert, 0, len(infos))
	highestLevel := config.AlertLevelInfo

	for _, info := range infos {
		alert := f.createAlert(info, cfg)
		if alert.Level > highestLevel {
			highestLevel = alert.Level
		}
		alerts = append(alerts, alert)
	}

	// Sort alerts by severity (most critical first)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Level > alerts[j].Level
	})

	if f.jsonMode {
		f.outputJSON(alerts)
	} else {
		f.outputText(alerts, cfg)
	}

	return highestLevel
}

// createAlert builds an Alert from certificate info using config thresholds.
func (f *AlertFormatter) createAlert(info *checker.CertInfo, cfg *config.Config) *Alert {
	level := cfg.GetAlertLevel(info.DaysUntilExpiry)

	var message string
	if info.Error != "" {
		message = info.Error
		level = config.AlertLevelCritical
	} else {
		message = f.generateMessage(level, info.DaysUntilExpiry)
	}

	return &Alert{
		Level:           level,
		Domain:          info.Domain,
		CommonName:      info.CommonName,
		SubjectAltNames: info.SubjectAltNames,
		Issuer:          info.Issuer,
		ExpiryDate:      info.NotAfter,
		DaysUntilExpiry: info.DaysUntilExpiry,
		SerialNumber:    info.SerialNumber,
		Message:         message,
		CheckedAt:       info.CheckedAt,
		Error:           info.Error,
	}
}

// generateMessage creates a human-readable message based on alert level.
func (f *AlertFormatter) generateMessage(level config.AlertLevel, days float64) string {
	switch level {
	case config.AlertLevelExpired:
		return fmt.Sprintf("Certificate has expired %.0f days ago", -days)
	case config.AlertLevelCritical:
		return fmt.Sprintf("Certificate expires in %.0f days - immediate action required", days)
	case config.AlertLevelWarning:
		return fmt.Sprintf("Certificate expires in %.0f days - renewal recommended", days)
	default:
		weeks := days / 7
		return fmt.Sprintf("Certificate valid for %.0f weeks (%.0f days)", weeks, days)
	}
}

// outputText writes alerts in human-readable format with optional colors.
func (f *AlertFormatter) outputText(alerts []*Alert, cfg *config.Config) {
	// Print summary header
	summary := f.calculateSummary(alerts)
	f.printSummary(summary)

	f.println()
	f.println("Certificate Details:")
	f.println(strings.Repeat("-", 70))

	for _, alert := range alerts {
		// In quiet mode, skip INFO-level alerts without errors
		if f.quietMode && alert.Level == config.AlertLevelInfo && alert.Error == "" {
			continue
		}

		f.printAlert(alert)
	}

	f.println()
	f.printRecommendations(alerts, cfg)
}

// printSummary displays aggregate statistics about checked certificates.
func (f *AlertFormatter) printSummary(summary *AlertSummary) {
	f.println()
	f.println("TLS Certificate Expiry Summary")
	f.println(strings.Repeat("=", 40))
	f.printf("Total certificates checked: %d\n", summary.TotalChecked)
	f.printf("Healthy (>%d days):         %d\n", 30, summary.Healthy)
	f.printf("Warning (≤%d days):         %d\n", 30, summary.WarningCount)
	f.printf("Critical (≤%d days):        %d\n", 7, summary.CriticalCount)
	f.printf("Expired:                    %d\n", summary.ExpiredCount)
	if summary.ErrorCount > 0 {
		f.printf("Errors:                     %d\n", summary.ErrorCount)
	}
	f.println(strings.Repeat("=", 40))
}

// printAlert outputs a single alert with appropriate formatting.
func (f *AlertFormatter) printAlert(alert *Alert) {
	color := ""
	reset := ""

	if !f.noColor && os.Getenv("NO_COLOR") == "" {
		color = alert.Level.Color()
		reset = "\033[0m"
	}

	status := fmt.Sprintf("[%s]", alert.Level.String())
	if color != "" {
		status = color + status + reset
	}

	f.printf("%s %s\n", status, alert.Domain)

	if alert.Error != "" {
		f.printf("  Error: %s\n", alert.Error)
	} else {
		f.printf("  Expires: %s (%s)\n",
			alert.ExpiryDate.Format("2006-01-02"),
			checker.FormatDaysUntilExpiry(alert.DaysUntilExpiry))
		f.printf("  Issuer: %s\n", alert.Issuer)
		if alert.CommonName != "" && alert.CommonName != alert.Domain {
			f.printf("  Common Name: %s\n", alert.CommonName)
		}
		if len(alert.SubjectAltNames) > 1 {
			f.printf("  SANs: %s\n", strings.Join(alert.SubjectAltNames[:min(3, len(alert.SubjectAltNames))], ", "))
			if len(alert.SubjectAltNames) > 3 {
				f.printf("        ... and %d more\n", len(alert.SubjectAltNames)-3)
			}
		}
	}
	f.println()
}

// printRecommendations provides actionable advice based on alert results.
func (f *AlertFormatter) printRecommendations(alerts []*Alert, cfg *config.Config) {
	var criticalAlerts, expiredAlerts []*Alert

	for _, alert := range alerts {
		if alert.Level == config.AlertLevelCritical && alert.Error == "" {
			criticalAlerts = append(criticalAlerts, alert)
		}
		if alert.Level == config.AlertLevelExpired {
			expiredAlerts = append(expiredAlerts, alert)
		}
	}

	if len(expiredAlerts) > 0 {
		f.println("⚠️  ACTION REQUIRED: Expired Certificates")
		f.println("   The following certificates have already expired:")
		for _, alert := range expiredAlerts {
			f.printf("   - %s\n", alert.Domain)
		}
		f.println("   Renew immediately to restore secure connections.")
		f.println()
	}

	if len(criticalAlerts) > 0 {
		f.println("⚠️  URGENT: Certificates Expiring Soon")
		f.println("   The following certificates need immediate renewal:")
		for _, alert := range criticalAlerts {
			f.printf("   - %s (expires in %.0f days)\n", alert.Domain, alert.DaysUntilExpiry)
		}
		f.println()
	}
}

// outputJSON writes alerts in JSON format for programmatic consumption.
func (f *AlertFormatter) outputJSON(alerts []*Alert) {
	output := struct {
		Timestamp time.Time  `json:"timestamp"`
		Alerts    []*Alert   `json:"alerts"`
		Summary   *AlertSummary `json:"summary"`
	}{
		Timestamp: time.Now(),
		Alerts:    alerts,
		Summary:   f.calculateSummary(alerts),
	}

	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

// calculateSummary computes aggregate statistics from alerts.
func (f *AlertFormatter) calculateSummary(alerts []*Alert) *AlertSummary {
	summary := &AlertSummary{
		TotalChecked: len(alerts),
	}

	var totalDays float64
	validCount := 0

	for _, alert := range alerts {
		switch alert.Level {
		case config.AlertLevelInfo:
			summary.Healthy++
		case config.AlertLevelWarning:
			summary.WarningCount++
		case config.AlertLevelCritical:
			if alert.Error != "" {
				summary.ErrorCount++
			} else {
				summary.CriticalCount++
			}
		case config.AlertLevelExpired:
			summary.ExpiredCount++
		}

		if alert.Error == "" && alert.DaysUntilExpiry > 0 {
			totalDays += alert.DaysUntilExpiry
			validCount++
		}
	}

	if validCount > 0 {
		summary.AverageDaysLeft = totalDays / float64(validCount)
	}

	return summary
}

func (f *AlertFormatter) println(s ...string) {
	fmt.Fprintln(f.writer, strings.Join(s, ""))
}

func (f *AlertFormatter) printf(format string, args ...interface{}) {
	fmt.Fprintf(f.writer, format, args...)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
