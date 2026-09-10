//go:build windows

package checks

import "strings"

// canVerifySignatures reports whether this platform can answer the question
// "was this file signed by a publisher we can name".
func canVerifySignatures() bool { return true }

// verifySignatures returns the signing authority of every path whose
// Authenticode signature verifies. A path absent from the map either carries no
// signature at all, or one that does not verify.
//
// The second return value says whether the verification actually ran. That
// distinction is the whole point: an empty map means "none of these files is
// signed", while a failed run means "we do not know". Treating the second as
// the first would raise a critical alert on lsass.exe because PowerShell did
// not answer, which is how a tool loses the trust of the person reading it.
func verifySignatures(paths []string) (map[string]string, bool) {
	res := map[string]string{}
	if len(paths) == 0 {
		return res, true
	}

	var quoted []string
	for _, p := range paths {
		quoted = append(quoted, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}

	// Only the common name of the subject is kept. The rest of the
	// distinguished name, the locality and the country, tells the reader
	// nothing they need at the moment they are deciding whether a system
	// binary was replaced.
	script := "@(" + strings.Join(quoted, ",") + ") | ForEach-Object { " +
		"$s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; " +
		"if ($s -and $s.Status -eq 'Valid') { " +
		"$n = $s.SignerCertificate.Subject -replace '^CN=([^,]+).*$','$1'; " +
		"\"$_|$n\" } }"

	out, err := psCmd(script)
	if err != nil {
		return nil, false
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		i := strings.LastIndex(l, "|")
		if i <= 0 {
			continue
		}
		res[strings.ToLower(l[:i])] = strings.TrimSpace(l[i+1:])
	}
	return res, true
}
