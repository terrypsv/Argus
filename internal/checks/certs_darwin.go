//go:build darwin

package checks

import (
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
)

// macOS keeps Apple's shipped anchors and locally installed ones in separate
// keychains, so the distinction between vendor and local needs no guesswork.
const (
	appleRootKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"
	systemKeychain    = "/Library/Keychains/System.keychain"
)

func certStoreCheck(ctx *engine.Context) []model.Finding {
	if !cmdAvailable("security") {
		return []model.Finding{errFinding("CERT-ROOT-INV", "certificates",
			"Could not read the trusted root store",
			"The security command is unavailable, so the keychains were not read.")}
	}

	var all []certInfo
	for _, k := range []struct {
		path  string
		local bool
	}{
		{appleRootKeychain, false},
		{systemKeychain, true},
	} {
		out, err := runCmd(30*time.Second, "security", "find-certificate", "-a", "-p", k.path)
		if err != nil && strings.TrimSpace(out) == "" {
			continue
		}
		all = append(all, parsePEMCerts(out, k.local)...)
	}

	findings := rootStoreFindings(all, "Apple anchors plus the system keychain")

	// An administrator trust override changes whether a certificate is trusted
	// without changing which certificates are present, so it is invisible to
	// the inventory above and has to be read separately.
	if out, err := runCmd(20*time.Second, "security", "dump-trust-settings", "-d"); err == nil {
		if !strings.Contains(out, "No Trust Settings were found") && strings.TrimSpace(out) != "" {
			var lines []string
			for _, l := range strings.Split(out, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					lines = append(lines, trunc(l, 120))
				}
			}
			findings = append(findings, info("CERT-TRUSTOVERRIDE", "certificates",
				"Administrator trust overrides are configured",
				"Someone changed the trust decision for one or more certificates on this machine. That can grant trust the vendor did not, or revoke trust the vendor did.",
				capEvidence(lines)...))
		}
	}

	return findings
}
