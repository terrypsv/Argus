// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized copying prohibited.

// Package schema projette un rapport Argus sur le schema de constat partage, pour
// qu'Acta l'agrege avec le reste de la suite. La projection preserve la regle
// centrale d'Argus: l'axe durcissement/integrite de chaque constat est porte en
// evidence, et un constat sciemment accepte ou deja compte ailleurs garde sa vraie
// gravite sans etre rejuge. Comme Warden et Regula, les controles satisfaits sont
// comptes (dans le contexte du run) mais pas listes: le schema partage porte les
// problemes, pas les reussites.
package schema

import (
	"crypto/rand"
	"encoding/hex"

	"argus/internal/finding"
	"argus/internal/model"
)

// ToSchema convertit un model.Report d'Argus en finding.Report partage.
func ToSchema(m *model.Report) *finding.Report {
	ctx := map[string]any{
		"os":              m.Host.OS,
		"arch":            m.Host.Arch,
		"score":           m.Score,
		"grade":           m.Grade,
		"hardening_score": m.Hardening.Score,
		"integrity_score": m.Integrity.Score,
		"controls":        len(m.Findings),
	}
	if m.Profile != "" {
		ctx["profile"] = m.Profile
	}
	if len(m.Counts) > 0 {
		ctx["counts"] = m.Counts
	}

	rep := &finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Tool:          finding.Tool{Name: "argus", Version: m.Version},
		Run: finding.Run{
			ID:         newRunID(),
			StartedAt:  m.StartedAt,
			FinishedAt: m.FinishedAt,
			Host:       m.Host.Hostname,
			Context:    ctx,
		},
		Findings: make([]finding.Finding, 0, len(m.Findings)),
	}

	for i := range m.Findings {
		f := project(m, &m.Findings[i])
		if f.Status == finding.StatusPass {
			continue // controle satisfait: compte, pas liste
		}
		rep.Findings = append(rep.Findings, f)
	}
	return rep
}

func project(m *model.Report, mf *model.Finding) finding.Finding {
	out := finding.Finding{
		ID:          "ARG-" + mf.ID,
		Title:       mf.Title,
		Category:    mf.Category,
		Severity:    severity(mf.Severity),
		Status:      status(mf),
		Target:      &finding.Target{Type: "host", Identifier: m.Host.Hostname},
		Observed:    mf.Detail,
		Remediation: mf.Remediation,
		DetectedAt:  m.FinishedAt,
	}

	// Un constat accepte reste visible avec sa vraie gravite; on le marque declare.
	if mf.Accepted != "" {
		out.Declared = finding.Bool(true)
	}

	// L'axe est la regle centrale d'Argus: on le porte en premiere evidence.
	out.Evidence = append(out.Evidence, finding.Evidence{Type: "axis", Data: model.AxisOf(*mf).String()})
	if mf.Err != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "error", Data: mf.Err})
	}
	if mf.Accepted != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "accepted", Data: mf.Accepted})
	}
	if mf.Superseded != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "superseded", Data: "deja compte par " + mf.Superseded})
	}
	for _, e := range mf.Evidence {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "detail", Data: e})
	}

	// References publiees (MITRE ATT&CK, ANSSI-BP-028, CIS), reprises une a une.
	for _, r := range mf.References {
		out.References = append(out.References, finding.Reference{Framework: r.Framework, ID: r.ID, Title: r.Title})
	}
	return out
}

// status traduit l'etat d'un constat Argus vers le schema partage:
// un controle qui n'a pas pu s'executer, ou une exception connue, sort en review;
// un controle satisfait passe; sinon c'est un echec.
func status(mf *model.Finding) finding.Status {
	switch {
	case mf.Err != "":
		return finding.StatusReview
	case mf.Passed:
		return finding.StatusPass
	case mf.Accepted != "":
		return finding.StatusReview
	default:
		return finding.StatusFail
	}
}

func severity(s model.Severity) finding.Severity {
	switch s {
	case model.SevCritical:
		return finding.SeverityCritical
	case model.SevHigh:
		return finding.SeverityHigh
	case model.SevMedium:
		return finding.SeverityMedium
	case model.SevLow:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

func newRunID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
