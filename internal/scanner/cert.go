package scanner

import (
	"crypto/tls"
	"strings"
	"time"
)

// Known legitimate issuers for Cloudflare and Fastly certificates.
var knownCDNIssuers = map[string][]string{
	"cloudflare": {
		"cloudflare",
		"digicert",
		"google trust services",
		"let's encrypt",
		"globalsign",
		"baltimore cybertrust",
		"sectigo",
	},
	"fastly": {
		"globalsign",
		"digicert",
		"let's encrypt",
		"amazon",
		"certainly",
		"r3",
		"e1",
	},
}

// CertInfo holds parsed certificate validation results.
type CertInfo struct {
	Issuer  string
	Subject string
	Expiry  string
	MITM    bool
}

// ValidateCert inspects the TLS connection state and determines whether the
// certificate chain looks legitimate for the given CDN provider. If the issuer
// doesn't match any known CDN issuer, MITM is flagged.
func ValidateCert(state tls.ConnectionState, provider string) CertInfo {
	info := CertInfo{}
	if len(state.PeerCertificates) == 0 {
		info.MITM = true
		return info
	}

	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.CommonName
	info.Expiry = leaf.NotAfter.Format(time.RFC3339)

	issuerOrg := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuerOrg = leaf.Issuer.Organization[0]
	}
	if issuerOrg == "" {
		issuerOrg = leaf.Issuer.CommonName
	}
	info.Issuer = issuerOrg

	if provider == "" {
		return info
	}

	trusted := knownCDNIssuers[provider]
	if trusted == nil {
		trusted = knownCDNIssuers["cloudflare"]
	}

	issuerLower := strings.ToLower(issuerOrg)
	cnLower := strings.ToLower(leaf.Issuer.CommonName)
	matched := false
	for _, known := range trusted {
		if strings.Contains(issuerLower, known) || strings.Contains(cnLower, known) {
			matched = true
			break
		}
	}
	info.MITM = !matched
	return info
}
