//go:build windows

package checks

import (
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// microsoftAnchors are the publishers whose roots Windows ships in the machine
// store by design. They are absent from AuthRoot because they are not third
// party, so without this they would every one read as locally installed.
//
// This is a name test, and a name test is weak. It is used only to decide
// whether a root is worth surfacing for review, never to clear one: a certificate
// claiming to be Microsoft still appears in the full inventory, and the diff
// still reports it as an addition.
// Matching is deliberately restricted to the organisation fields. Testing the
// whole subject would swallow "Symantec Enterprise Mobile Root for Microsoft",
// a Symantec root that merely names Microsoft, and hide a third-party anchor.
var microsoftAnchors = []string{
	"o=microsoft corporation",
	"ou=microsoft corporation",
	"dc=microsoft",
}

// certStoreCheck reads the machine's trusted roots.
//
// Windows has no directory reserved for administrator-added anchors the way
// Debian and macOS do, so "locally installed" has to be inferred: AuthRoot holds
// what Microsoft's Trusted Root Program delivers, Root holds what the machine
// actually trusts. A certificate present in Root but not in AuthRoot was put
// there by something on this machine.
//
// That inference is what makes the check independent of any catalogue of
// interception products: it does not need to recognise a vendor to notice that
// a root was added.
func certStoreCheck(ctx *engine.Context) []model.Finding {
	out, err := psCmd(
		`$auth=@{}; ` +
			`Get-ChildItem Cert:\LocalMachine\AuthRoot -ErrorAction SilentlyContinue | ` +
			`ForEach-Object { $auth[$_.Thumbprint]=1 }; ` +
			`Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | ForEach-Object { ` +
			`$l = if ($auth.ContainsKey($_.Thumbprint)) { "0" } else { "1" }; ` +
			`"$($_.Thumbprint)|$($_.NotAfter.ToString('yyyy-MM-dd'))|$l|$($_.Subject)" }`)
	if err != nil && strings.TrimSpace(out) == "" {
		return []model.Finding{errFinding("CERT-ROOT-INV", "certificates",
			"Could not read the trusted root store",
			"PowerShell returned nothing for the machine certificate stores, so nothing is claimed about the machine's trust anchors.")}
	}

	var all []certInfo
	for _, line := range strings.Split(out, "\n") {
		if c, ok := parseWinCertLine(line); ok {
			all = append(all, c)
		}
	}
	return rootStoreFindings(all, "machine Trusted Root store")
}

// parseWinCertLine reads "THUMBPRINT|yyyy-mm-dd|localFlag|Subject". The subject
// is taken as the remainder rather than as a field, because a distinguished name
// can itself contain the separator.
func parseWinCertLine(line string) (certInfo, bool) {
	parts := strings.SplitN(strings.TrimSpace(line), "|", 4)
	if len(parts) < 4 {
		return certInfo{}, false
	}
	thumb := strings.ToLower(strings.TrimSpace(parts[0]))
	if len(thumb) < 16 || strings.Trim(thumb, "0123456789abcdef") != "" {
		return certInfo{}, false // header, blank line, or wrapped output
	}
	expires, err := time.Parse("2006-01-02", strings.TrimSpace(parts[1]))
	if err != nil {
		return certInfo{}, false
	}
	subject := strings.TrimSpace(parts[3])
	if subject == "" {
		return certInfo{}, false
	}
	// Outside the Trusted Root Program and not one of Windows' own anchors.
	local := strings.TrimSpace(parts[2]) == "1" &&
		!containsAny(strings.ToLower(subject), microsoftAnchors...)

	return certInfo{subject: subject, expires: expires, sha1: thumb, local: local}, true
}
