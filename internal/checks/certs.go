package checks

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"argus/internal/model"
)

// A trusted root certificate is the most leveraged object on a machine. Anyone
// holding the matching private key can issue a certificate for any domain, and
// every browser on the host will accept it silently. That makes the root store
// worth watching, and it is the one place where "what changed" matters far more
// than "what is there": a legitimate store holds dozens of vendor roots, so a
// reference list would drift constantly, while a root that appeared since the
// last scan is unambiguous.
//
// The inventory findings here are therefore registered as watched inventories in
// the diff engine, which is what turns this from a list into a detection.

// certInfo is one trusted root, reduced to what a report needs.
type certInfo struct {
	subject string
	expires time.Time
	sha1    string
	local   bool // added on this machine rather than shipped by the vendor
}

// label renders a certificate as a stable inventory line. The fingerprint comes
// first so that two certificates sharing a subject stay distinguishable, and so
// that a re-issued certificate reads as a change rather than as noise.
func (c certInfo) label() string {
	return fmt.Sprintf("%s  %s  (expires %s)",
		c.sha1[:16], trunc(c.subject, 90), c.expires.Format("2006-01-02"))
}

// interceptionMarkers name products that install a root in order to decrypt
// TLS. Matching on names is a weak signal by construction: it recognises the
// commercial products that announce themselves, and it will never catch an
// attacker who names their root "DigiCert Global Root CA". It is the diff on
// the inventory, not this list, that covers the stealthy case.
var interceptionMarkers = []string{
	"ssl filter", "ssl inspection", "ssl proxy", "ssl scanner",
	"deep packet", "decrypt", "mitmproxy", "fiddler", "charles proxy",
	"portswigger", "zscaler", "netskope", "bluecoat", "blue coat",
	"forcepoint", "websense", "cloudflare warp", "sophos utm",
	"kaspersky anti-virus personal root", "avast trusted ca",
	"bitdefender personal ca", "eset ssl filter",
}

func looksLikeInterception(subject string) bool {
	return containsAny(strings.ToLower(subject), interceptionMarkers...)
}

// parsePEMCerts decodes a PEM stream into certificates, ignoring anything that
// is not a parseable certificate. A malformed entry is skipped rather than
// aborting the check: one bad block in a bundle of a hundred must not cost the
// other ninety-nine.
func parsePEMCerts(data string, local bool) []certInfo {
	var out []certInfo
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha1.Sum(c.Raw)
		out = append(out, certInfo{
			subject: certSubject(c),
			expires: c.NotAfter,
			sha1:    hex.EncodeToString(sum[:]),
			local:   local,
		})
	}
	return out
}

// certSubject prefers the common name and falls back to the organisation, since
// some roots carry only one of the two.
func certSubject(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return strings.Join(c.Subject.Organization, ", ")
	}
	return c.Subject.String()
}

// rootStoreFindings turns a collected store into findings. It is shared by all
// three platforms so that the same situation reads the same way everywhere,
// whatever the command used to gather the certificates.
func rootStoreFindings(all []certInfo, vendorLabel string) []model.Finding {
	if len(all) == 0 {
		return []model.Finding{errFinding("CERT-ROOT-INV", "certificates",
			"Could not read the trusted root store",
			"No certificate could be parsed. Nothing is claimed about the machine's trust anchors.")}
	}

	now := time.Now()
	var inventory, localOnes, intercept, expired []string
	seen := map[string]bool{}

	for _, c := range all {
		if seen[c.sha1] {
			continue // present in more than one store; count the trust once
		}
		seen[c.sha1] = true

		inventory = append(inventory, c.label())
		if c.local {
			localOnes = append(localOnes, c.label())
		}
		if looksLikeInterception(c.subject) {
			intercept = append(intercept, c.label())
		}
		if c.expires.Before(now) {
			expired = append(expired, c.label())
		}
	}
	sort.Strings(inventory)
	sort.Strings(localOnes)
	sort.Strings(intercept)
	sort.Strings(expired)

	var out []model.Finding

	if len(intercept) > 0 {
		out = append(out, fail("CERT-INTERCEPT", "certificates",
			fmt.Sprintf("%d trusted root(s) belong to a TLS interception product", len(intercept)),
			model.SevMedium,
			"Traffic to every HTTPS site on this machine is decrypted and re-encrypted by the holder of this root. That is how antivirus and corporate proxies inspect TLS, and it means a leak of that private key would let anyone forge any site for this host.",
			"If this is deliberate, record the decision: argus accept CERT-INTERCEPT --reason \"...\". Otherwise remove the root and find out how it got there.",
			cap50(intercept)...))
	}

	if len(localOnes) > 0 {
		out = append(out, info("CERT-LOCAL", "certificates",
			fmt.Sprintf("%d trusted root(s) were added on this machine", len(localOnes)),
			"These are not shipped by the operating system vendor. Each one can vouch for any domain, so each should correspond to something you installed on purpose.",
			cap50(localOnes)...))
	}

	if len(expired) > 0 {
		out = append(out, info("CERT-EXPIRED", "certificates",
			fmt.Sprintf("%d trusted root(s) have expired", len(expired)),
			"An expired root cannot validate a new chain, so this is housekeeping rather than exposure. Not scored for that reason.",
			cap50(expired)...))
	}

	out = append(out, info("CERT-ROOT-INV", "certificates",
		fmt.Sprintf("%d trusted root certificate(s) (%s)", len(inventory), vendorLabel),
		"Any one of these can vouch for any domain. A root that appeared since the previous scan is the signal worth acting on; compare with argus diff.",
		cap50(inventory)...))

	return out
}
