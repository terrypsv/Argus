package model

import "testing"

func TestReferencesForKnownFindings(t *testing.T) {
	cases := []struct {
		id        string
		framework Framework
		refID     string
	}{
		{"RUN-SUSP", FrameworkMITRE, "T1547.001"},
		{"PROC-MEMFD", FrameworkMITRE, "T1620"},
		{"KRN-LDPRELOAD", FrameworkMITRE, "T1574.006"},
		{"KRN-TAINT", FrameworkMITRE, "T1014"},
		{"SUID-SUSP", FrameworkMITRE, "T1548.001"},
		{"AV-RTP", FrameworkMITRE, "T1562.001"},
		{"KRN-KERNEL-YAMA-PTRACE_SCOPE", FrameworkANSSI, "R25"},
	}
	for _, c := range cases {
		refs := ReferencesFor(c.id)
		if len(refs) == 0 {
			t.Errorf("ReferencesFor(%q) returned nothing", c.id)
			continue
		}
		found := false
		for _, r := range refs {
			if r.Framework == c.framework && r.ID == c.refID {
				found = true
			}
		}
		if !found {
			t.Errorf("ReferencesFor(%q) = %v, want %s %s", c.id, refs, c.framework, c.refID)
		}
	}
}

func TestReferencesForIsCaseInsensitive(t *testing.T) {
	if len(ReferencesFor("run-susp")) == 0 {
		t.Error("lookup must not depend on the case of the finding ID")
	}
}

// An unmapped finding must return nothing rather than a placeholder: callers
// have to be able to tell "not yet mapped" from "no standard covers this".
func TestReferencesForUnknownFindingReturnsNothing(t *testing.T) {
	if refs := ReferencesFor("PAS-UN-VRAI-ID"); refs != nil {
		t.Errorf("got %v, want nil", refs)
	}
}

func TestNormaliseAttachesReferences(t *testing.T) {
	f := Finding{ID: "PROC-MEMFD", Severity: SevCritical}
	f.Normalise()
	if len(f.References) == 0 {
		t.Fatal("Normalise must attach the published controls to the finding")
	}
	if f.SeverityStr != "CRITICAL" {
		t.Errorf("SeverityStr = %q, want CRITICAL", f.SeverityStr)
	}
}

// A reference supplied by a check must win over the table, so a future check
// can carry a control the table does not know yet.
func TestNormaliseKeepsExplicitReferences(t *testing.T) {
	custom := Reference{Framework: FrameworkCIS, ID: "1.2.3", Title: "Un controle"}
	f := Finding{ID: "PROC-MEMFD", References: []Reference{custom}}
	f.Normalise()
	if len(f.References) != 1 || f.References[0].ID != "1.2.3" {
		t.Errorf("references = %v, want the explicit one preserved", f.References)
	}
}

func TestReferenceString(t *testing.T) {
	r := Reference{Framework: FrameworkANSSI, ID: "R25", Title: "Yama"}
	if got := r.String(); got != "ANSSI-BP-028 R25" {
		t.Errorf("String() = %q, want %q", got, "ANSSI-BP-028 R25")
	}
}

func TestCoverageStatsIsHonest(t *testing.T) {
	mapped, frameworks := CoverageStats()
	if mapped == 0 {
		t.Fatal("no finding is mapped to any standard")
	}
	if len(frameworks) < 2 {
		t.Errorf("frameworks = %v, want at least MITRE ATT&CK and ANSSI-BP-028", frameworks)
	}
}
