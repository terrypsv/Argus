package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Argus/internal/model"
)

func TestLookupProfile(t *testing.T) {
	if p, err := LookupProfile(""); err != nil || p.Name != "workstation" {
		t.Errorf("empty name gave %q, %v; want the workstation default", p.Name, err)
	}
	if p, err := LookupProfile("  AUDIT "); err != nil || p.Name != "audit" {
		t.Errorf("lookup must trim and ignore case, got %q, %v", p.Name, err)
	}
	if _, err := LookupProfile("nimportequoi"); err == nil {
		t.Error("an unknown profile must be rejected rather than silently ignored")
	} else if !strings.Contains(err.Error(), "workstation") {
		t.Errorf("the error should list the available profiles, got %q", err)
	}
}

// The default profile must waive nothing, or a plain scan would quietly
// under-report.
func TestWorkstationWaivesNothing(t *testing.T) {
	p, _ := LookupProfile("workstation")
	if len(p.exceptions()) != 0 {
		t.Errorf("workstation carries %d waiver(s), want none", len(p.exceptions()))
	}
}

// A profile may soften a hardening expectation. It must never touch the
// integrity axis: no class of machine is allowed to be tampered with.
func TestProfilesNeverWaiveIntegrity(t *testing.T) {
	for _, name := range ProfileNames() {
		p, _ := LookupProfile(name)
		for id := range p.Waivers {
			if model.AxisOf(model.Finding{ID: id}) == model.AxisIntegrity {
				t.Errorf("profile %q waives %s, which is an integrity finding", name, id)
			}
		}
	}
}

func TestProfileWaiversCarryAJustification(t *testing.T) {
	for _, name := range ProfileNames() {
		p, _ := LookupProfile(name)
		for _, e := range p.exceptions() {
			if len(strings.TrimSpace(e.Reason)) < 20 {
				t.Errorf("profile %q: waiver %s has no usable justification (%q)", name, e.ID, e.Reason)
			}
			if !strings.Contains(e.Reason, name) {
				t.Errorf("profile %q: waiver %s should name its profile, got %q", name, e.ID, e.Reason)
			}
			if e.Expires != "" {
				t.Errorf("profile %q: waiver %s must not expire; a profile describes the machine", name, e.ID)
			}
		}
	}
}

func TestAuditProfileWaivesPtraceButNotTheFirewall(t *testing.T) {
	p, _ := LookupProfile("audit")
	if _, ok := p.Waivers["KRN-KERNEL-YAMA-PTRACE_SCOPE"]; !ok {
		t.Error("a pentest workstation needs unrestricted ptrace")
	}
	if _, ok := p.Waivers["FW-NONE"]; ok {
		t.Error("an audit machine on a hostile network still wants a firewall")
	}
}

func TestContainerProfileWaivesHostOwnedSettings(t *testing.T) {
	p, _ := LookupProfile("container")
	for _, id := range []string{"KRN-KERNEL-KPTR_RESTRICT", "MNT-NOEXEC-TMP", "FW-NONE"} {
		if _, ok := p.Waivers[id]; !ok {
			t.Errorf("%s is not settable from inside a container and should be waived", id)
		}
	}
}

// A profile waiver behaves exactly like a human one: visible, justified, and
// excluded from the score without touching the raw score.
func TestProfileWaiverKeepsTheRawScoreHonest(t *testing.T) {
	findings := []model.Finding{
		{ID: "MNT-NOEXEC-TMP", Severity: model.SevMedium},
		{ID: "BL-OFF", Severity: model.SevMedium},
	}
	p, _ := LookupProfile("audit")
	ef := ExceptionFile{Exceptions: p.exceptions()}

	if n, _ := applyExceptions(findings, ef, time.Now()); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	s := axisScore(findings, model.AxisHardening)
	if s.Score != 93 {
		t.Errorf("score = %d, want 93 with the waiver applied", s.Score)
	}
	if s.RawScore != 86 {
		t.Errorf("raw score = %d, want 86: a profile must not rewrite the truth", s.RawScore)
	}
	if findings[0].Accepted == "" || !strings.Contains(findings[0].Accepted, "audit") {
		t.Errorf("the waived finding should name the profile, got %q", findings[0].Accepted)
	}
}
