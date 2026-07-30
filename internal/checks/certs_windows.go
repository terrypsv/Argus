//go:build windows

package checks

import (
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
)

// Windows has no separation between shipped and locally installed roots: the
// machine's Trusted Root store holds Microsoft's anchors, the ones delivered by
// the Trusted Root Program, and anything an administrator or installer added,
// all mixed together. Nothing can be labelled local with confidence, so the
// check reports the store as a whole and leaves the detection to the diff: a
// root that appeared since the last scan is the signal.
func certStoreCheck(ctx *engine.Context) []model.Finding {
	out, err := psCmd(`Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object { ` +
		`"$($_.Thumbprint)|$($_.NotAfter.ToString('yyyy-MM-dd'))|$($_.Subject)" }`)
	if err != nil && strings.TrimSpace(out) == "" {
		return []model.Finding{errFinding("CERT-ROOT-INV", "certificates",
			"Could not read the trusted root store",
			"PowerShell returned nothing for Cert:\\LocalMachine\\Root, so nothing is claimed about the machine's trust anchors.")}
	}

	var all []certInfo
	for _, line := range strings.Split(out, "\n") {
		if c, ok := parseWinCertLine(line); ok {
			all = append(all, c)
		}
	}
	return rootStoreFindings(all, "machine Trusted Root store")
}

// parseWinCertLine reads "THUMBPRINT|yyyy-mm-dd|Subject". The subject is taken
// as the remainder rather than as a field, because a distinguished name can
// itself contain the separator.
func parseWinCertLine(line string) (certInfo, bool) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, "|", 3)
	if len(parts) < 3 {
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
	subject := strings.TrimSpace(parts[2])
	if subject == "" {
		return certInfo{}, false
	}
	// Every certificate in this store is trusted the same way, and none of them
	// can be attributed to a local install with confidence.
	return certInfo{subject: subject, expires: expires, sha1: thumb, local: false}, true
}
