package model

import "testing"

// The axis split is the heart of the report: a misclassified finding turns a
// hardening recommendation into an intrusion alert, or hides a real one.
func TestAxisOf(t *testing.T) {
	cases := []struct {
		id   string
		want Axis
	}{
		{"PROC-MEMFD", AxisIntegrity},
		{"PROC-DELETED", AxisIntegrity},
		{"INTEG-CHANGED", AxisIntegrity},
		{"RUN-SUSP", AxisIntegrity},
		{"ACC-UID0", AxisIntegrity},
		{"SUID-SUSP", AxisIntegrity},
		{"KEXT-3RD", AxisIntegrity},
		{"KRN-TAINT", AxisIntegrity},
		{"KRN-LDPRELOAD", AxisIntegrity},

		// A kernel sysctl is configuration, not evidence of tampering, even
		// though it shares the KRN- prefix with the two entries above.
		{"KRN-KERNEL-KPTR_RESTRICT", AxisHardening},

		// macOS: an enabled guest account is a configuration weakness, not
		// evidence of tampering. Naming it ACC-GUEST would have put it on the
		// integrity axis through the ACC- prefix.
		{"GUEST-ON", AxisHardening},
		{"SSH-REMOTE", AxisHardening},
		{"VNC-ON", AxisHardening},
		{"ARD-ALLUSERS", AxisHardening},
		{"SSV-OFF", AxisHardening},
		{"UPD-NOCHECK", AxisHardening},
		{"SYSEXT-ACTIVE", AxisHardening},

		// A trust anchor is configuration. Putting it on the integrity axis would
		// make every machine with an antivirus that inspects TLS read as tampered.
		{"CERT-INTERCEPT", AxisHardening},
		{"CERT-LOCAL", AxisHardening},
		{"CERT-ROOT-INV", AxisHardening},
		{"KRN-HARDENING", AxisHardening},
		{"MNT-NOEXEC-TMP", AxisHardening},
		{"FW-NONE", AxisHardening},
		{"NET-PORT-445", AxisHardening},
		{"BL-OFF", AxisHardening},
		{"AV-RTP", AxisHardening},
		{"SSH-PWAUTH", AxisHardening},
	}
	for _, c := range cases {
		if got := AxisOf(Finding{ID: c.id}); got != c.want {
			t.Errorf("AxisOf(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical} {
		if got := SeverityFromString(s.String()); got != s {
			t.Errorf("round trip of %v gave %v", s, got)
		}
	}
	if got := SeverityFromString("n'importe quoi"); got != SevInfo {
		t.Errorf("unknown label gave %v, want SevInfo", got)
	}
}

func TestSeverityWeights(t *testing.T) {
	if SevInfo.Weight() != 0 {
		t.Error("informational findings must never cost points")
	}
	weights := []float64{
		SevLow.Weight(), SevMedium.Weight(), SevHigh.Weight(), SevCritical.Weight(),
	}
	for i := 1; i < len(weights); i++ {
		if weights[i] <= weights[i-1] {
			t.Errorf("weights must increase with severity, got %v", weights)
			break
		}
	}
}

// The reporters print a fixed-width tag for each severity. This is the bug that
// a LOW finding in an accepted section triggered: String()[:4] panics on "LOW".
func TestSeverityAbbrevIsAlwaysFourChars(t *testing.T) {
	for _, s := range []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical} {
		if got := s.Abbrev(); len(got) != 4 {
			t.Errorf("Abbrev(%v) = %q (%d chars), want exactly 4", s, got, len(got))
		}
	}
}
