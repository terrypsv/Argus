package engine

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/terrypsv/Argus/internal/model"
)

func day(s string) time.Time {
	t, _ := time.Parse(DateLayout, s)
	return t
}

func TestExceptionExpiry(t *testing.T) {
	now := day("2026-07-23")

	if (Exception{}).Expired(now) {
		t.Error("an exception with no expiry date must never expire")
	}
	if (Exception{Expires: "2026-08-01"}).Expired(now) {
		t.Error("a future expiry must not be treated as expired")
	}
	if !(Exception{Expires: "2026-07-01"}).Expired(now) {
		t.Error("a past expiry must be treated as expired")
	}
	// A typo in the date must not make an acceptance vanish without a word.
	if (Exception{Expires: "pas-une-date"}).Expired(now) {
		t.Error("an unparsable date must not expire the exception")
	}
}

// The whole point of the design: an accepted finding is tagged, never erased.
func TestApplyExceptionsTagsWithoutHiding(t *testing.T) {
	findings := []model.Finding{{ID: "BL-OFF", Severity: model.SevMedium}}
	ef := ExceptionFile{Exceptions: []Exception{
		{ID: "bl-off", Reason: "poste fixe"},
	}}

	n, expired := applyExceptions(findings, ef, day("2026-07-23"))
	if n != 1 {
		t.Fatalf("suppressed = %d, want 1 (matching must ignore case)", n)
	}
	if len(expired) != 0 {
		t.Errorf("expired = %v, want none", expired)
	}

	f := findings[0]
	if f.Accepted != "poste fixe" {
		t.Errorf("accepted reason = %q, want it recorded on the finding", f.Accepted)
	}
	if f.Passed {
		t.Error("an accepted finding must not be marked as passed")
	}
	if f.Severity != model.SevMedium {
		t.Error("an accepted finding must keep its real severity for the raw score")
	}
}

func TestApplyExceptionsIgnoresExpired(t *testing.T) {
	findings := []model.Finding{{ID: "BL-OFF", Severity: model.SevMedium}}
	ef := ExceptionFile{Exceptions: []Exception{
		{ID: "BL-OFF", Reason: "temporaire", Expires: "2026-01-01"},
	}}

	n, expired := applyExceptions(findings, ef, day("2026-07-23"))
	if n != 0 {
		t.Errorf("suppressed = %d, want 0", n)
	}
	if len(expired) != 1 || expired[0] != "BL-OFF" {
		t.Errorf("expired = %v, want [BL-OFF]", expired)
	}
	if findings[0].Accepted != "" {
		t.Error("an expired exception must not neutralise the finding")
	}
}

func TestApplyExceptionsLeavesPassedFindingsAlone(t *testing.T) {
	findings := []model.Finding{{ID: "FW-ON", Severity: model.SevInfo, Passed: true}}
	ef := ExceptionFile{Exceptions: []Exception{{ID: "FW-ON", Reason: "peu importe"}}}

	if n, _ := applyExceptions(findings, ef, day("2026-07-23")); n != 0 {
		t.Errorf("suppressed = %d, want 0: there is nothing to waive on a passing control", n)
	}
}

func TestExceptionFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.json")

	for _, e := range []Exception{
		{ID: "BL-OFF", Reason: "un"},
		{ID: "NET-PORT-445", Reason: "deux"},
		{ID: "BL-OFF", Reason: "revise"}, // same ID: replace, never duplicate
	} {
		if err := AddException(path, e); err != nil {
			t.Fatalf("AddException(%s): %v", e.ID, err)
		}
	}

	ef, err := LoadExceptions(path)
	if err != nil {
		t.Fatalf("LoadExceptions: %v", err)
	}
	if len(ef.Exceptions) != 2 {
		t.Fatalf("got %d exceptions, want 2", len(ef.Exceptions))
	}
	for _, e := range ef.Exceptions {
		if e.ID == "BL-OFF" && e.Reason != "revise" {
			t.Errorf("BL-OFF reason = %q, want the replacement", e.Reason)
		}
	}

	removed, err := RemoveException(path, "bl-off")
	if err != nil || !removed {
		t.Fatalf("RemoveException = %v, %v; want true, nil", removed, err)
	}
	ef, _ = LoadExceptions(path)
	if len(ef.Exceptions) != 1 {
		t.Errorf("got %d exceptions after removal, want 1", len(ef.Exceptions))
	}

	if removed, _ := RemoveException(path, "INEXISTANT"); removed {
		t.Error("removing an unknown ID must report false")
	}
}

func TestLoadExceptionsMissingFileIsNotAnError(t *testing.T) {
	ef, err := LoadExceptions(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Errorf("missing file returned %v, want nil", err)
	}
	if len(ef.Exceptions) != 0 {
		t.Error("a missing file must yield no exceptions")
	}
}
