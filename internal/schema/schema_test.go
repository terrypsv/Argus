// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized copying prohibited.

package schema_test

import (
	"testing"
	"time"

	"argus/internal/finding"
	"argus/internal/model"
	"argus/internal/schema"
)

func sampleReport() *model.Report {
	return &model.Report{
		Tool:       "argus",
		Version:    "1.2.0",
		Host:       model.HostInfo{Hostname: "poste-01", OS: "linux", Arch: "amd64"},
		StartedAt:  time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 7, 30, 9, 0, 5, 0, time.UTC),
		Score:      72,
		Grade:      "C",
		Hardening:  model.AxisScore{Score: 80, Grade: "B"},
		Integrity:  model.AxisScore{Score: 72, Grade: "C"},
		Counts:     map[string]int{"critical": 1, "high": 1},
		Findings: []model.Finding{
			{
				ID: "SSH-ROOT", Category: "network", Title: "SSH root autorise",
				Severity: model.SevHigh, Passed: false, Detail: "PermitRootLogin yes",
				Remediation: "PermitRootLogin no",
				References:  []model.Reference{{Framework: "MITRE ATT&CK", ID: "T1021", Title: "Remote Services"}},
			},
			{ID: "DISK-ENC", Category: "disk", Title: "Chiffrement disque actif", Severity: model.SevInfo, Passed: true},
			{ID: "SUID-FOUND", Category: "accounts", Title: "Binaire SUID inattendu", Severity: model.SevCritical, Passed: false, Detail: "/tmp/x", Evidence: []string{"/tmp/x"}},
			{ID: "ACC-GUEST", Category: "accounts", Title: "Compte invite", Severity: model.SevMedium, Passed: false, Accepted: "poste de demo"},
			{ID: "PKG-VERIFY", Category: "packages", Title: "Verif paquets impossible", Severity: model.SevLow, Passed: false, Err: "dpkg indisponible"},
		},
	}
}

func find(fs []finding.Finding, id string) (finding.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func hasEvidence(f finding.Finding, typ, data string) bool {
	for _, e := range f.Evidence {
		if e.Type == typ && e.Data == data {
			return true
		}
	}
	return false
}

func TestEnveloppe(t *testing.T) {
	r := schema.ToSchema(sampleReport())
	if r.SchemaVersion != finding.SchemaVersion {
		t.Fatalf("schema version: %s", r.SchemaVersion)
	}
	if r.Tool.Name != "argus" || r.Tool.Version != "1.2.0" {
		t.Fatalf("tool: %+v", r.Tool)
	}
	if r.Run.Host != "poste-01" {
		t.Fatalf("host: %s", r.Run.Host)
	}
	if r.Run.Context["controls"] != 5 {
		t.Fatalf("controls attendu 5, obtenu %v", r.Run.Context["controls"])
	}
	if r.Run.Context["score"] != 72 {
		t.Fatalf("score attendu 72, obtenu %v", r.Run.Context["score"])
	}
}

func TestControleSatisfaitNonListe(t *testing.T) {
	r := schema.ToSchema(sampleReport())
	if _, ok := find(r.Findings, "ARG-DISK-ENC"); ok {
		t.Fatal("un controle satisfait ne doit pas etre liste")
	}
	if len(r.Findings) != 4 {
		t.Fatalf("4 constats attendus (5 moins 1 satisfait), obtenu %d", len(r.Findings))
	}
}

func TestEchecAxeEtReference(t *testing.T) {
	r := schema.ToSchema(sampleReport())
	f, ok := find(r.Findings, "ARG-SSH-ROOT")
	if !ok {
		t.Fatal("ARG-SSH-ROOT attendu")
	}
	if f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("attendu fail/high, obtenu %s/%s", f.Status, f.Severity)
	}
	if !hasEvidence(f, "axis", "hardening") {
		t.Fatal("axe hardening attendu en evidence")
	}
	if f.Observed != "PermitRootLogin yes" {
		t.Fatalf("detail vers observed: %q", f.Observed)
	}
	if len(f.References) == 0 || f.References[0].ID != "T1021" {
		t.Fatalf("reference MITRE attendue: %+v", f.References)
	}
}

func TestIntegriteAccepteErreur(t *testing.T) {
	r := schema.ToSchema(sampleReport())

	suid, ok := find(r.Findings, "ARG-SUID-FOUND")
	if !ok || !hasEvidence(suid, "axis", "integrity") {
		t.Fatal("SUID-FOUND devrait etre classe axe integrity")
	}
	if suid.Status != finding.StatusFail {
		t.Fatalf("SUID-FOUND devrait etre fail, obtenu %s", suid.Status)
	}

	acc, ok := find(r.Findings, "ARG-ACC-GUEST")
	if !ok || acc.Status != finding.StatusReview {
		t.Fatalf("constat accepte devrait etre review, obtenu %v", acc.Status)
	}
	if acc.Declared == nil || !*acc.Declared {
		t.Fatal("constat accepte devrait porter declared=true")
	}
	if !hasEvidence(acc, "accepted", "poste de demo") {
		t.Fatal("raison d'acceptation attendue en evidence")
	}

	pkg, ok := find(r.Findings, "ARG-PKG-VERIFY")
	if !ok || pkg.Status != finding.StatusReview {
		t.Fatalf("controle en erreur devrait etre review, obtenu %v", pkg.Status)
	}
	if !hasEvidence(pkg, "error", "dpkg indisponible") {
		t.Fatal("erreur attendue en evidence")
	}
}
