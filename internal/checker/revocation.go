// Package checker provides TLS certificate inspection functionality.
// It handles the low-level network operations to fetch certificates
// and extract relevant expiry information.
package checker

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

// RevocationStatus represents the revocation state of a certificate.
type RevocationStatus int

const (
	// RevocationStatusUnknown indicates revocation status could not be determined.
	RevocationStatusUnknown RevocationStatus = iota
	// RevocationStatusGood indicates the certificate is not revoked.
	RevocationStatusGood
	// RevocationStatusRevoked indicates the certificate has been revoked.
	RevocationStatusRevoked
	// RevocationStatusNotFound indicates the certificate was not found in revocation lists.
	RevocationStatusNotFound
)

// String returns the human-readable name of the revocation status.
func (r RevocationStatus) String() string {
	switch r {
	case RevocationStatusUnknown:
		return "UNKNOWN"
	case RevocationStatusGood:
		return "GOOD"
	case RevocationStatusRevoked:
		return "REVOKED"
	case RevocationStatusNotFound:
		return "NOT_FOUND"
	default:
		return "UNKNOWN"
	}
}

// RevocationInfo holds information about certificate revocation status.
type RevocationInfo struct {
	// Status is the revocation status of the certificate.
	Status RevocationStatus
	// Method indicates how the status was determined (OCSP, CRL, or NONE).
	Method string
	// ReasonCode indicates why the certificate was revoked (if revoked).
	ReasonCode int
	// RevokedAt is when the certificate was revoked (if revoked).
	RevokedAt time.Time
	// NextUpdate is when to check again for status updates.
	NextUpdate time.Time
	// ProducedAt is when the OCSP response was produced.
	ProducedAt time.Time
	// ResponderURL is the URL of the responder that provided the status.
	ResponderURL string
	// Error contains any error that occurred during checking.
	Error string
}

// CheckRevocation checks if a certificate has been revoked using OCSP and CRL.
// It tries OCSP first, then falls back to CRL if OCSP is unavailable.
func CheckRevocation(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate, timeout time.Duration) *RevocationInfo {
	info := &RevocationInfo{
		Status: RevocationStatusUnknown,
		Method: "NONE",
	}

	// Try OCSP first
	if len(cert.OCSPServer) > 0 {
		info = checkOCSP(ctx, cert, issuer, cert.OCSPServer[0], timeout)
		if info.Status != RevocationStatusUnknown && info.Error == "" {
			return info
		}
	}

	// Fall back to CRL if OCSP didn't provide a definitive answer
	if len(cert.CRLDistributionPoints) > 0 {
		crlInfo := checkCRL(ctx, cert, issuer, cert.CRLDistributionPoints, timeout)
		if crlInfo.Status != RevocationStatusUnknown {
			return crlInfo
		}
	}

	return info
}

// checkOCSP queries an OCSP responder to check certificate revocation status.
func checkOCSP(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate, ocspURL string, timeout time.Duration) *RevocationInfo {
	info := &RevocationInfo{
		Status:       RevocationStatusUnknown,
		Method:       "OCSP",
		ResponderURL: ocspURL,
	}

	// Build OCSP request
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		info.Error = fmt.Sprintf("failed to create OCSP request: %v", err)
		return info
	}

	// Parse the OCSP URL
	parsedURL, err := url.Parse(ocspURL)
	if err != nil {
		info.Error = fmt.Sprintf("invalid OCSP URL: %v", err)
		return info
	}

	// Determine request method (POST for most responders)
	var respData []byte
	if parsedURL.Scheme == "http" {
		respData, err = sendOCSPRequestHTTP(ctx, ocspURL, request, timeout)
	} else {
		info.Error = fmt.Sprintf("unsupported OCSP URL scheme: %s", parsedURL.Scheme)
		return info
	}

	if err != nil {
		info.Error = fmt.Sprintf("OCSP request failed: %v", err)
		return info
	}

	// Parse OCSP response
	response, err := ocsp.ParseResponse(respData, issuer)
	if err != nil {
		info.Error = fmt.Sprintf("failed to parse OCSP response: %v", err)
		return info
	}

	info.ProducedAt = response.ProducedAt
	if response.NextUpdate.After(time.Time{}) {
		info.NextUpdate = response.NextUpdate
	}

	// Check the status
	switch response.Status {
	case ocsp.Good:
		info.Status = RevocationStatusGood
	case ocsp.Revoked:
		info.Status = RevocationStatusRevoked
		info.RevokedAt = response.RevokedAt
		info.ReasonCode = response.ReasonCode
	case ocsp.Unknown:
		info.Status = RevocationStatusUnknown
		info.Error = "OCSP responder returned unknown status"
	}

	return info
}

// sendOCSPRequestHTTP sends an OCSP request via HTTP POST.
func sendOCSPRequestHTTP(ctx context.Context, ocspURL string, request []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", ocspURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	// Encode request in URL for GET or use POST body
	encodedRequest := base64.StdEncoding.EncodeToString(request)
	
	// Some OCSP responders accept GET requests with encoded request in URL
	if len(encodedRequest) < 255 {
		getURL := ocspURL
		if getURL[len(getURL)-1] != '/' {
			getURL += "/"
		}
		getURL += encodedRequest
		
		getReq, err := http.NewRequestWithContext(ctx, "GET", getURL, nil)
		if err != nil {
			return nil, err
		}
		getReq.Header.Set("Accept", "application/ocsp-response")
		
		client := &http.Client{
			Timeout: timeout,
		}
		resp, err := client.Do(getReq)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}
	}

	// Fall back to POST
	client := &http.Client{
		Timeout: timeout,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder returned status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// checkCRL checks certificate revocation status against CRL distribution points.
func checkCRL(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate, crlURLs []string, timeout time.Duration) *RevocationInfo {
	info := &RevocationInfo{
		Status: RevocationStatusUnknown,
		Method: "CRL",
	}

	for _, crlURL := range crlURLs {
		crlInfo := fetchAndCheckCRL(ctx, cert, issuer, crlURL, timeout)
		if crlInfo.Status != RevocationStatusUnknown || crlInfo.Error == "" {
			info = crlInfo
			info.ResponderURL = crlURL
			if crlInfo.Status != RevocationStatusUnknown {
				return info
			}
		}
	}

	return info
}

// fetchAndCheckCRL fetches a CRL and checks if the certificate is listed.
func fetchAndCheckCRL(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate, crlURL string, timeout time.Duration) *RevocationInfo {
	info := &RevocationInfo{
		Status: RevocationStatusUnknown,
		Method: "CRL",
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", crlURL, nil)
	if err != nil {
		info.Error = fmt.Sprintf("failed to create CRL request: %v", err)
		return info
	}

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		info.Error = fmt.Sprintf("CRL fetch failed: %v", err)
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("CRL endpoint returned status: %d", resp.StatusCode)
		return info
	}

	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		info.Error = fmt.Sprintf("failed to read CRL data: %v", err)
		return info
	}

	// Try to parse as DER-encoded CRL first
	crl, err := x509.ParseRevocationList(crlData)
	if err != nil {
		// Try PEM-encoded CRL
		block, _ := pem.Decode(crlData)
		if block != nil {
			crl, err = x509.ParseRevocationList(block.Bytes)
		}
	}

	if err != nil {
		info.Error = fmt.Sprintf("failed to parse CRL: %v", err)
		return info
	}

	info.NextUpdate = crl.NextUpdate
	info.ProducedAt = crl.ThisUpdate

	// Check if certificate serial number is in the CRL
	serialNumber := cert.SerialNumber
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			info.Status = RevocationStatusRevoked
			info.RevokedAt = revoked.RevocationTime
			info.ReasonCode = getReasonCode(revoked.Extensions)
			return info
		}
	}

	info.Status = RevocationStatusGood
	return info
}

// getReasonCode extracts the CRL reason code from extensions.
func getReasonCode(extensions []pkix.Extension) int {
	// RFC 5280: id-ce-cRLReasons OID
	reasonCodeOID := asn1.ObjectIdentifier{2, 5, 29, 21}

	for _, ext := range extensions {
		if ext.Id.Equal(reasonCodeOID) {
			var reasonCode int
			if _, err := asn1.Unmarshal(ext.Value, &reasonCode); err == nil {
				return reasonCode
			}
		}
	}

	return 0 // unspecified
}

// GetIssuerCertificate attempts to find the issuer certificate for a given certificate.
// It checks the provided certificate chain first, then attempts to fetch from AIA.
func GetIssuerCertificate(cert *x509.Certificate, chain []*x509.Certificate, timeout time.Duration) (*x509.Certificate, error) {
	// Check if issuer is in the provided chain
	for _, potentialIssuer := range chain {
		if potentialIssuer.Subject.String() == cert.Issuer.String() {
			// Verify the signature to confirm it's the actual issuer
			if err := cert.CheckSignatureFrom(potentialIssuer); err == nil {
				return potentialIssuer, nil
			}
		}
	}

	// Try to fetch issuer from AIA (Authority Information Access)
	if len(cert.IssuingCertificateURL) > 0 {
		for _, issuerURL := range cert.IssuingCertificateURL {
			issuerCert, err := fetchCertificateFromURL(issuerURL, timeout)
			if err != nil {
				continue
			}

			// Verify this is indeed the issuer
			if err := cert.CheckSignatureFrom(issuerCert); err == nil {
				return issuerCert, nil
			}
		}
	}

	return nil, fmt.Errorf("issuer certificate not found")
}

// fetchCertificateFromURL fetches a certificate from a URL.
func fetchCertificateFromURL(certURL string, timeout time.Duration) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", certURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate URL returned status: %d", resp.StatusCode)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try DER first
	cert, err := x509.ParseCertificate(certData)
	if err == nil {
		return cert, nil
	}

	// Try PEM
	block, _ := pem.Decode(certData)
	if block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("failed to parse certificate from URL")
}

// GetRevocationReasonString returns a human-readable string for a reason code.
func GetRevocationReasonString(reasonCode int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "key compromise",
		2:  "CA compromise",
		3:  "affiliation changed",
		4:  "superseded",
		5:  "cessation of operation",
		6:  "certificate hold",
		8:  "remove from CRL",
		9:  "privilege withdrawn",
		10: "AA compromise",
	}

	if reason, ok := reasons[reasonCode]; ok {
		return reason
	}
	return fmt.Sprintf("unknown (%d)", reasonCode)
}
