package engine

import (
	"strings"
	"testing"

	"argus/internal/model"
)

func failing(id string, sev model.Severity) model.Finding {
	return model.Finding{ID: id, Severity: sev}
}

func TestAxisScoreKeepsAxesIndependent(t *testing.T) {
	findings := []model.Finding{
		failing("MNT-NOEXEC-TMP", model.SevMedium), // hardening, -7
		failing("FW-NONE", model.SevMedium),        // hardening, -7
		failing("PROC-MEMFD", model.SevCritical),   // integrity, -35
	}
	hard := axisScore(findings, model.AxisHardening)
	integ := axisScore(findings, model.AxisIntegrity)

	if hard.Score != 86 || hard.Issues != 2 {
		t.Errorf("hardening = %d/%d issues, want 86/2", hard.Score, hard.Issues)
	}
	if integ.Score != 65 || integ.Issues != 1 {
		t.Errorf("integrity = %d/%d issues, want 65/1", integ.Score, integ.Issues)
	}
}

// A waiver must lower neither the raw score nor the count of what is carried,
// otherwise accepting a finding would quietly look like fixing it.
func TestAxisScoreExcludesAcceptedButPublishesRaw(t *testing.T) {
	findings := []model.Finding{
		failing("BL-OFF", model.SevMedium),
		{ID: "NET-PORT-445", Severity: model.SevMedium, Accepted: "partage LAN"},
	}
	s := axisScore(findings, model.AxisHardening)
	if s.Score != 93 {
		t.Errorf("score = %d, want 93 (accepted finding excluded)", s.Score)
	}
	if s.RawScore != 86 {
		t.Errorf("raw score = %d, want 86 (accepted finding still counted)", s.RawScore)
	}
	if s.Accepted != 1 || s.Issues != 1 {
		t.Errorf("accepted = %d, issues = %d, want 1 and 1", s.Accepted, s.Issues)
	}
}

func TestAxisScoreClampsAtZero(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, failing("PROC-MEMFD", model.SevCritical))
	}
	if got := axisScore(findings, model.AxisIntegrity).Score; got != 0 {
		t.Errorf("score = %d, want 0", got)
	}
}

func TestPassedAndInfoNeverPenalise(t *testing.T) {
	findings := []model.Finding{
		{ID: "FW-ON", Severity: model.SevInfo, Passed: true},
		{ID: "NET-LISTEN", Severity: model.SevInfo, Passed: true},
	}
	if got := axisScore(findings, model.AxisHardening).Score; got != 100 {
		t.Errorf("score = %d, want 100", got)
	}
}

// A perfectly hardened but compromised host must never read as healthy.
func TestVerdictPrioritisesIntegrity(t *testing.T) {
	v := verdict(
		model.AxisScore{Score: 100},
		model.AxisScore{Score: 50, Issues: 1},
	)
	if !strings.Contains(strings.ToLower(v), "compromise") {
		t.Errorf("verdict = %q, want it to lead with the compromise", v)
	}
}

func TestVerdictMentionsAcceptedFindings(t *testing.T) {
	v := verdict(
		model.AxisScore{Score: 100, Accepted: 2},
		model.AxisScore{Score: 100},
	)
	if !strings.Contains(v, "accepted") {
		t.Errorf("verdict = %q, want the waived findings mentioned", v)
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[int]string{
		100: "A", 90: "A", 89: "B", 80: "B", 79: "C", 70: "C",
		69: "D", 60: "D", 59: "E", 40: "E", 39: "F", 0: "F",
	}
	for score, want := range cases {
		if got := grade(score); got != want {
			t.Errorf("grade(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestCountFindingsSeparatesAcceptedFromPassed(t *testing.T) {
	findings := []model.Finding{
		{ID: "FW-ON", Severity: model.SevInfo, Passed: true},
		{ID: "BL-OFF", Severity: model.SevMedium},
		{ID: "NET-PORT-445", Severity: model.SevMedium, Accepted: "partage LAN"},
	}
	c := countFindings(findings)
	if c["passed"] != 1 || c["failed"] != 1 || c["accepted"] != 1 {
		t.Errorf("passed %d, failed %d, accepted %d; want 1, 1, 1",
			c["passed"], c["failed"], c["accepted"])
	}
	if c["MEDIUM"] != 1 {
		t.Errorf("MEDIUM = %d, want 1 (the accepted one must not be tallied)", c["MEDIUM"])
	}
}

// Enabling one setting should cost points once. Screen Sharing fires both a
// service finding and a port finding; charging for both makes the score a
// function of how many checks noticed, not of the machine's posture.
func TestCorrelateReachabilityChargesOnce(t *testing.T) {
	findings := []model.Finding{
		failing("VNC-ON", model.SevMedium),
		failing("NET-PORT-TCP-5900", model.SevMedium),
		failing("FW-OFF", model.SevMedium),
	}
	correlateReachability(findings)

	if findings[0].Superseded != "NET-PORT-TCP-5900" {
		t.Errorf("VNC-ON superseded = %q, want the port finding", findings[0].Superseded)
	}
	if findings[1].Superseded != "" {
		t.Error("the port finding is the one that charges; it must not be superseded itself")
	}

	s := axisScore(findings, model.AxisHardening)
	if s.Score != 86 {
		t.Errorf("score = %d, want 86: two deductions, not three", s.Score)
	}
	if s.RawScore != 86 {
		t.Errorf("raw score = %d, want 86: the raw score excludes waivers, not double counting", s.RawScore)
	}
}

// A service enabled but not reachable is a real, uncharged-elsewhere finding.
// This is the case that justifies keeping the service check at all.
func TestServiceEnabledButFirewalledStillCounts(t *testing.T) {
	findings := []model.Finding{failing("VNC-ON", model.SevMedium)}
	correlateReachability(findings)

	if findings[0].Superseded != "" {
		t.Error("with no port finding present, nothing has charged for this yet")
	}
	if got := axisScore(findings, model.AxisHardening).Score; got != 93 {
		t.Errorf("score = %d, want 93", got)
	}
}

// The finding must stay visible and keep its severity: it explains why the
// port is open, and a report that states a symptom without its cause is worse.
func TestSupersededFindingStaysVisible(t *testing.T) {
	findings := []model.Finding{
		failing("RDP-ON", model.SevMedium),
		failing("NET-PORT-TCP-3389", model.SevMedium),
	}
	correlateReachability(findings)

	if findings[0].Passed {
		t.Error("a superseded finding is not a passed control")
	}
	if findings[0].Severity != model.SevMedium {
		t.Error("a superseded finding keeps its real severity")
	}
	if c := countFindings(findings); c["failed"] != 2 {
		t.Errorf("failed = %d, want 2: both remain open problems", c["failed"])
	}
}
