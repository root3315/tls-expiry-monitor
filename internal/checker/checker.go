// Package checker provides TLS certificate inspection functionality.
// It handles the low-level network operations to fetch certificates
// and extract relevant expiry information.
package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds extracted information from a TLS certificate.
// This structure contains only the fields relevant for expiry monitoring.
type CertInfo struct {
	// Domain is the hostname that was checked.
	Domain string
	// CommonName is the certificate's subject common name.
	CommonName string
	// SubjectAltNames lists all DNS names and IPs covered by the certificate.
	SubjectAltNames []string
	// Issuer is the certificate authority that issued the certificate.
	Issuer string
	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time
	// NotAfter is when the certificate expires.
	NotAfter time.Time
	// DaysUntilExpiry is the number of days remaining until expiration.
	// Negative values indicate the certificate has already expired.
	DaysUntilExpiry float64
	// SerialNumber is the certificate's unique serial number.
	SerialNumber string
	// SignatureAlgorithm indicates the cryptographic algorithm used.
	SignatureAlgorithm string
	// CheckedAt records when the certificate was fetched.
	CheckedAt time.Time
	// Error contains any error that occurred during checking.
	Error string
	// Revocation contains the certificate revocation status.
	Revocation *RevocationInfo
}

// Checker performs TLS certificate checks against remote hosts.
type Checker struct {
	timeout          time.Duration
	checkRevocation  bool
}

// NewChecker creates a new Checker with the specified timeout.
// The timeout applies to each individual TLS handshake operation.
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{
		timeout:         timeout,
		checkRevocation: false,
	}
}

// NewCheckerWithRevocation creates a new Checker with revocation checking enabled.
func NewCheckerWithRevocation(timeout time.Duration, checkRevocation bool) *Checker {
	return &Checker{
		timeout:         timeout,
		checkRevocation: checkRevocation,
	}
}

// CheckDomain performs a TLS handshake and extracts certificate information.
// This is the primary method for checking a single domain's certificate status.
func (c *Checker) CheckDomain(domain string) *CertInfo {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	info := &CertInfo{
		Domain:    domain,
		CheckedAt: time.Now(),
	}

	// Parse host and port for the TLS connection
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// If no port specified, default to 443
		host = domain
		port = "443"
		domain = host + ":443"
		info.Domain = domain
	}

	// Configure TLS to skip verification - we only care about expiry, not trust
	// This allows checking self-signed certificates and internal PKI
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	// Establish TCP connection first to get better error messages
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", domain)
	if err != nil {
		info.Error = fmt.Sprintf("connection failed: %v", err)
		return info
	}
	defer conn.Close()

	// Perform TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		info.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		return info
	}
	defer tlsConn.Close()

	// Extract certificate from the connection state
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		info.Error = "no certificates received from server"
		return info
	}

	// Use the leaf certificate (first in chain) for expiry checking
	cert := state.PeerCertificates[0]
	info = c.extractCertInfo(cert, domain, state.PeerCertificates)

	// Perform revocation check if enabled
	if c.checkRevocation && info.Error == "" {
		info.Revocation = c.checkRevocationStatus(ctx, cert, state.PeerCertificates)
	}

	return info
}

// extractCertInfo pulls relevant fields from an x509 certificate.
// We only extract fields needed for monitoring to keep the data structure lean.
func (c *Checker) extractCertInfo(cert *x509.Certificate, domain string, chain []*x509.Certificate) *CertInfo {
	now := time.Now()
	timeUntilExpiry := cert.NotAfter.Sub(now)

	// Combine DNS names and IP addresses from SANs
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// If no SANs, fall back to CommonName
	if len(sans) == 0 && cert.Subject.CommonName != "" {
		sans = []string{cert.Subject.CommonName}
	}

	return &CertInfo{
		Domain:             domain,
		CommonName:         cert.Subject.CommonName,
		SubjectAltNames:    sans,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    timeUntilExpiry.Hours() / 24,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		CheckedAt:          now,
		Revocation:         nil,
	}
}

// checkRevocationStatus performs revocation checking using OCSP and CRL.
func (c *Checker) checkRevocationStatus(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) *RevocationInfo {
	// Try to find issuer certificate in the chain
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	} else {
		// Try to fetch issuer from AIA
		var err error
		issuer, err = GetIssuerCertificate(cert, chain, c.timeout)
		if err != nil {
			return &RevocationInfo{
				Status: RevocationStatusUnknown,
				Method: "NONE",
				Error:  fmt.Sprintf("issuer not available: %v", err),
			}
		}
	}

	return CheckRevocation(ctx, cert, issuer, c.timeout)
}

// CheckDomains checks multiple domains concurrently.
// Results are returned in the same order as the input domains slice.
func (c *Checker) CheckDomains(domains []string) []*CertInfo {
	results := make([]*CertInfo, len(domains))

	// Use a channel to collect results in order
	type result struct {
		index int
		info  *CertInfo
	}

	resultChan := make(chan result, len(domains))

	// Launch concurrent checks
	for i, domain := range domains {
		go func(idx int, d string) {
			info := c.CheckDomain(d)
			resultChan <- result{index: idx, info: info}
		}(i, domain)
	}

	// Collect all results
	for i := 0; i < len(domains); i++ {
		r := <-resultChan
		results[r.index] = r.info
	}

	return results
}

// CheckDomainsSequential checks domains one at a time.
// Use this when rate limiting is a concern or for debugging.
func (c *Checker) CheckDomainsSequential(domains []string) []*CertInfo {
	results := make([]*CertInfo, len(domains))

	for i, domain := range domains {
		results[i] = c.CheckDomain(domain)
	}

	return results
}

// FormatDaysUntilExpiry returns a human-readable string for days remaining.
func FormatDaysUntilExpiry(days float64) string {
	if days < 0 {
		absDays := -days
		if absDays > 365 {
			years := absDays / 365
			return fmt.Sprintf("expired %.1f years ago", years)
		}
		return fmt.Sprintf("expired %.0f days ago", absDays)
	}

	if days < 1 {
		hours := days * 24
		if hours < 1 {
			minutes := hours * 60
			return fmt.Sprintf("%.0f minutes", minutes)
		}
		return fmt.Sprintf("%.1f hours", hours)
	}

	if days < 30 {
		return fmt.Sprintf("%.0f days", days)
	}

	weeks := days / 7
	if weeks < 52 {
		return fmt.Sprintf("%.0f weeks (%.0f days)", weeks, days)
	}

	months := days / 30
	return fmt.Sprintf("%.0f months (%.0f days)", months, days)
}

// IsWildcardDomain checks if a domain string is a wildcard certificate.
func IsWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

// GetCertificateChainLength returns the number of certificates in a chain.
// This can be useful for debugging PKI issues.
func GetCertificateChainLength(domain string, timeout time.Duration) (int, error) {
	checker := NewChecker(timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		host = domain
		port = "443"
		domain = host + ":443"
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", domain)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	defer tlsConn.Close()

	return len(tlsConn.ConnectionState().PeerCertificates), nil
}
