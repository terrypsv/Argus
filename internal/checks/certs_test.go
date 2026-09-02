package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Argus/internal/model"
)

func findByID(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func cert(subject string, local bool, expires time.Time, fp string) certInfo {
	return certInfo{subject: subject, local: local, expires: expires, sha1: fp}
}

// The real case from a Windows machine: an antivirus root that decrypts TLS.
func TestLooksLikeInterception(t *testing.T) {
	positives := []string{
		`C=SK, O="ESET, spol. s r. o.", CN=ESET SSL Filter CA`,
		"Zscaler Root CA",
		"Fiddler Root Certificate Authority",
		"PortSwigger CA",
		"BlueCoat SSL Inspection",
		"mitmproxy",
	}
	for _, s := range positives {
		if !looksLikeInterception(s) {
			t.Errorf("looksLikeInterception(%q) = false, want true", s)
		}
	}

	negatives := []string{
		"DigiCert Trusted Root G4",
		"Microsoft Root Certificate Authority 2011",
		"ISRG Root X1",
		"Logitech Inc",
		"GlobalSign Root CA",
	}
	for _, s := range negatives {
		if looksLikeInterception(s) {
			t.Errorf("looksLikeInterception(%q) = true, want false", s)
		}
	}
}

func TestRootStoreFindingsClassifies(t *testing.T) {
	past := time.Now().AddDate(-2, 0, 0)
	future := time.Now().AddDate(5, 0, 0)

	findings := rootStoreFindings([]certInfo{
		cert("DigiCert Trusted Root G4", false, future, strings.Repeat("a", 40)),
		cert("ESET SSL Filter CA", false, future, strings.Repeat("b", 40)),
		cert("Microsoft Root Authority", false, past, strings.Repeat("c", 40)),
		cert("Mon AC interne", true, future, strings.Repeat("d", 40)),
	}, "test store")

	if f := findByID(findings, "CERT-INTERCEPT"); f == nil {
		t.Error("the interception root was not reported")
	} else if f.Severity != model.SevMedium {
		t.Errorf("CERT-INTERCEPT severity = %v, want medium", f.Severity)
	}

	if f := findByID(findings, "CERT-LOCAL"); f == nil {
		t.Error("the locally added root was not reported")
	} else if len(f.Evidence) != 1 {
		t.Errorf("CERT-LOCAL evidence = %d entries, want 1", len(f.Evidence))
	}

	if f := findByID(findings, "CERT-EXPIRED"); f == nil {
		t.Error("the expired root was not reported")
	} else if f.Severity != model.SevInfo {
		t.Error("an expired root cannot validate a chain, so it must not be scored")
	}

	inv := findByID(findings, "CERT-ROOT-INV")
	if inv == nil {
		t.Fatal("the inventory is missing")
	}
	if len(inv.Evidence) != 4 {
		t.Errorf("inventory = %d entries, want 4", len(inv.Evidence))
	}
}

// The same certificate can sit in more than one store. Counting the trust twice
// would inflate the inventory and produce phantom changes in a diff.
func TestRootStoreFindingsDeduplicatesByFingerprint(t *testing.T) {
	fp := strings.Repeat("e", 40)
	future := time.Now().AddDate(3, 0, 0)
	findings := rootStoreFindings([]certInfo{
		cert("Une racine", false, future, fp),
		cert("Une racine", true, future, fp),
	}, "test store")

	inv := findByID(findings, "CERT-ROOT-INV")
	if inv == nil || len(inv.Evidence) != 1 {
		t.Fatalf("inventory should hold a single entry, got %v", inv)
	}
}

// An unreadable store must not read as an empty one: a machine with no trust
// anchors is impossible, so zero means the check failed.
func TestRootStoreFindingsRefusesToClaimAnEmptyStore(t *testing.T) {
	findings := rootStoreFindings(nil, "test store")
	if len(findings) != 1 || findings[0].Err == "" {
		t.Fatalf("an empty store must produce a check error, got %v", findings)
	}
}

// Inventory lines are what the diff compares, so they must be stable across
// scans and must distinguish two certificates sharing a subject.
func TestCertLabelIsStableAndDistinguishing(t *testing.T) {
	when := time.Date(2030, 1, 2, 15, 4, 5, 0, time.UTC)
	a := cert("Meme sujet", false, when, strings.Repeat("1", 40))
	b := cert("Meme sujet", false, when, strings.Repeat("2", 40))

	if a.label() != a.label() {
		t.Error("the label must be deterministic")
	}
	if a.label() == b.label() {
		t.Error("two certificates sharing a subject must produce different labels")
	}
	if !strings.Contains(a.label(), "2030-01-02") {
		t.Errorf("label = %q, want the expiry date in it", a.label())
	}
}
