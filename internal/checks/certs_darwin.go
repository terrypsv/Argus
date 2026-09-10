//go:build darwin

package checks

import (
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
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
			"Magasin de racines de confiance illisible",
			"La commande security est indisponible, les trousseaux n'ont donc pas été lus.")}
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

	findings := rootStoreFindings(all, "ancres Apple et trousseau système")

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
				"Des remplacements de confiance administrateur sont configurés",
				"Quelqu'un a modifié la décision de confiance pour un ou plusieurs certificats de cette machine. Cela peut accorder une confiance que l'éditeur n'accordait pas, ou retirer celle qu'il accordait.",
				capEvidence(lines)...))
		}
	}

	return findings
}
