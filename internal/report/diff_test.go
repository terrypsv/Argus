package report

import (
	"testing"

	"argus/internal/model"
)

func mkReport(findings ...model.Finding) model.Report {
	return model.Report{Findings: findings}
}

func findChange(t *testing.T, d Diff, kind, id string) *Change {
	t.Helper()
	for i := range d.Changes {
		if d.Changes[i].Kind == kind && d.Changes[i].ID == id {
			return &d.Changes[i]
		}
	}
	return nil
}

func TestCompareDetectsNewAndResolved(t *testing.T) {
	before := mkReport(model.Finding{ID: "BL-OFF", Severity: model.SevMedium})
	after := mkReport(model.Finding{ID: "NET-PORT-445", Severity: model.SevMedium})

	d := Compare(before, after)
	if findChange(t, d, KindNew, "NET-PORT-445") == nil {
		t.Error("a problem absent from the previous scan must be reported as new")
	}
	if findChange(t, d, KindResolved, "BL-OFF") == nil {
		t.Error("a problem that disappeared must be reported as resolved")
	}
	if d.Alarming != 1 {
		t.Errorf("alarming = %d, want 1: only the new finding warrants attention", d.Alarming)
	}
}

func TestCompareDetectsSeverityMoves(t *testing.T) {
	worse := Compare(
		mkReport(model.Finding{ID: "SSH-PWAUTH", Severity: model.SevLow}),
		mkReport(model.Finding{ID: "SSH-PWAUTH", Severity: model.SevHigh}),
	)
	if findChange(t, worse, KindWorse, "SSH-PWAUTH") == nil {
		t.Error("an increase in severity must be reported")
	}

	better := Compare(
		mkReport(model.Finding{ID: "SSH-PWAUTH", Severity: model.SevHigh}),
		mkReport(model.Finding{ID: "SSH-PWAUTH", Severity: model.SevLow}),
	)
	if findChange(t, better, KindBetter, "SSH-PWAUTH") == nil {
		t.Error("a decrease in severity must be reported")
	}
}

func TestWaivingAFindingReadsAsResolved(t *testing.T) {
	d := Compare(
		mkReport(model.Finding{ID: "BL-OFF", Severity: model.SevMedium}),
		mkReport(model.Finding{ID: "BL-OFF", Severity: model.SevMedium, Accepted: "poste fixe"}),
	)
	if findChange(t, d, KindResolved, "BL-OFF") == nil {
		t.Error("waiving a finding must show as resolved, not linger as an unchanged failure")
	}
}

// The finding ID never changes when an attacker installs itself. The signal is
// a new line inside an inventory, which is what this test guards.
func TestCompareDetectsNewInventoryLine(t *testing.T) {
	before := mkReport(model.Finding{
		ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true,
		Evidence: []string{"tcp/443 (all interfaces)"},
	})
	after := mkReport(model.Finding{
		ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true,
		Evidence: []string{"tcp/443 (all interfaces)", "tcp/8123 (all interfaces)"},
	})

	d := Compare(before, after)
	c := findChange(t, d, KindAppeared, "NET-LISTEN")
	if c == nil {
		t.Fatal("a port that opened must be reported even though the finding ID did not change")
	}
	if c.Line != "tcp/8123 (all interfaces)" {
		t.Errorf("line = %q, want the newly opened port", c.Line)
	}
	if !c.Alarming {
		t.Error("a new listening port must require attention")
	}
}

func TestCompareIgnoresUnwatchedInventories(t *testing.T) {
	// Disk usage drifts on every scan; it is not an intrusion signal.
	d := Compare(
		mkReport(model.Finding{ID: "DISK-INV", Severity: model.SevInfo, Passed: true,
			Evidence: []string{"C: — 88% used"}}),
		mkReport(model.Finding{ID: "DISK-INV", Severity: model.SevInfo, Passed: true,
			Evidence: []string{"C: — 89% used"}}),
	)
	if len(d.Changes) != 0 {
		t.Errorf("got %d change(s), want 0 for an unwatched inventory", len(d.Changes))
	}
}

func TestEphemeralPortsAreFilteredOut(t *testing.T) {
	before := mkReport(model.Finding{
		ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true,
		Evidence: []string{"tcp/49664 (all interfaces)"},
	})
	after := mkReport(model.Finding{
		ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true,
		Evidence: []string{"tcp/60773 (local)"},
	})

	d := Compare(before, after)
	if len(d.Changes) != 0 {
		t.Errorf("got %d change(s), want 0: dynamic-range ports rebind on every boot", len(d.Changes))
	}
}

func TestNoisyEvidence(t *testing.T) {
	if !noisyEvidence("NET-LISTEN", "tcp/49664 (all interfaces)") {
		t.Error("ports in the IANA dynamic range must be filtered")
	}
	if !noisyEvidence("NET-LISTEN", "tcp/60773 (local)") {
		t.Error("ports in the IANA dynamic range must be filtered")
	}
	if noisyEvidence("NET-LISTEN", "tcp/445 (all interfaces)") {
		t.Error("well-known ports must never be filtered")
	}
	if noisyEvidence("NET-LISTEN", "tcp/8123 (all interfaces)") {
		t.Error("registered-range ports must never be filtered")
	}
	if noisyEvidence("RUN-INV", "quelque chose tcp/49664") {
		t.Error("the filter must apply only to the listening-port inventory")
	}
}

func TestCompareOnIdenticalReports(t *testing.T) {
	r := mkReport(
		model.Finding{ID: "BL-OFF", Severity: model.SevMedium},
		model.Finding{ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true,
			Evidence: []string{"tcp/443 (all interfaces)"}},
	)
	if d := Compare(r, r); len(d.Changes) != 0 {
		t.Errorf("got %d change(s) comparing a report with itself, want 0", len(d.Changes))
	}
}
