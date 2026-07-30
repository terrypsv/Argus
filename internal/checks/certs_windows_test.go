//go:build windows

package checks

import "testing"

// Windows reserves no directory for administrator-added anchors, so "locally
// installed" is inferred from AuthRoot membership. These cases pin that
// inference, including the Microsoft carve-out that keeps Windows' own anchors
// out of the review list.
func TestParseWinCertLine(t *testing.T) {
	const thumb = "ca3a9520aafa5490b1c2d3e4f5061728394a5b6c"

	cases := []struct {
		name    string
		line    string
		ok      bool
		local   bool
		subject string
	}{
		{
			// The real case: an antivirus root, in Root but not in AuthRoot.
			name: "third-party root outside the Trusted Root Program",
			line: thumb + `|2035-12-05|1|C=SK, O="ESET, spol. s r. o.", CN=ESET SSL Filter CA`,
			ok:   true, local: true,
			subject: `C=SK, O="ESET, spol. s r. o.", CN=ESET SSL Filter CA`,
		},
		{
			name: "root delivered by the Trusted Root Program",
			line: thumb + "|2038-01-15|0|CN=DigiCert Trusted Root G4, O=DigiCert Inc, C=US",
			ok:   true, local: false,
			subject: "CN=DigiCert Trusted Root G4, O=DigiCert Inc, C=US",
		},
		{
			// Absent from AuthRoot because it is not third party, so it must
			// not be reported as an addition.
			name: "Windows own anchor",
			line: thumb + "|2036-03-22|1|CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation",
			ok:   true, local: false,
			subject: "CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation",
		},
		{
			// A distinguished name can contain the separator, so the subject is
			// the remainder of the line rather than a field.
			name: "subject containing a pipe",
			line: thumb + `|2030-01-01|1|CN=Odd | Vendor, O=Test`,
			ok:   true, local: true,
			subject: `CN=Odd | Vendor, O=Test`,
		},
		{
			// A Symantec root that merely names Microsoft. Matching the whole
			// subject would have hidden it from the review list.
			name: "third-party root naming Microsoft",
			line: thumb + "|2032-03-15|1|CN=Symantec Enterprise Mobile Root for Microsoft, O=Symantec Corporation, C=US",
			ok:   true, local: true,
			subject: "CN=Symantec Enterprise Mobile Root for Microsoft, O=Symantec Corporation, C=US",
		},
		{name: "empty line", line: "", ok: false},
		{name: "too few fields", line: thumb + "|2030-01-01|1", ok: false},
		{name: "header row", line: "Thumbprint|NotAfter|Local|Subject", ok: false},
		{name: "unparseable date", line: thumb + "|pas-une-date|1|CN=X", ok: false},
		{name: "empty subject", line: thumb + "|2030-01-01|1|", ok: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseWinCertLine(c.line)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if got.subject != c.subject {
				t.Errorf("subject = %q, want %q", got.subject, c.subject)
			}
			if got.local != c.local {
				t.Errorf("local = %v, want %v", got.local, c.local)
			}
			if got.sha1 != thumb {
				t.Errorf("fingerprint = %q, want %q", got.sha1, thumb)
			}
		})
	}
}
