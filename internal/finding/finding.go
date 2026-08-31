// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized copying prohibited.

// Package finding porte le schema de constat commun a la suite (v1.0).
// Contrat gele: ajouts uniquement. Tout renommage, suppression ou changement
// de semantique d'un champ existant impose de passer SchemaVersion a "2.0".
// Copie canonique alignee sur celle de Warden.
package finding

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"time"
)

// SchemaVersion est la version du contrat. Ne pas modifier sans bump majeur.
const SchemaVersion = "1.0"

// Severity classe la gravite d'un constat.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Status est le verdict d'un controle.
type Status string

const (
	StatusPass   Status = "pass"
	StatusFail   Status = "fail"
	StatusReview Status = "review"
)

func (s Status) rank() int {
	switch s {
	case StatusFail:
		return 2
	case StatusReview:
		return 1
	default:
		return 0
	}
}

// Tool identifie l'outil emetteur.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Run decrit l'execution. Context est libre: chaque outil y met de quoi
// rejouer la mesure a l'identique.
type Run struct {
	ID         string         `json:"id"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Host       string         `json:"host"`
	Context    map[string]any `json:"context,omitempty"`
}

// Reference rattache un constat a un controle publie (MITRE, ANSSI, CIS).
type Reference struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
}

// Target designe l'objet du constat.
type Target struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// Evidence porte une preuve brute.
type Evidence struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// Finding est un constat unitaire.
type Finding struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Category    string      `json:"category"`
	Severity    Severity    `json:"severity"`
	Status      Status      `json:"status"`
	Target      *Target     `json:"target,omitempty"`
	Expected    string      `json:"expected,omitempty"`
	Observed    string      `json:"observed,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	Declared    *bool       `json:"declared,omitempty"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	References  []Reference `json:"references,omitempty"`
	DetectedAt  time.Time   `json:"detected_at"`
}

// Report est l'enveloppe complete emise par un outil.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	Run           Run       `json:"run"`
	Findings      []Finding `json:"findings"`
}

// NewReport ouvre un rapport horodate avec un identifiant de run aleatoire.
func NewReport(tool Tool, host string, ctx map[string]any) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		Run: Run{
			ID:        newRunID(),
			StartedAt: time.Now().UTC(),
			Host:      host,
			Context:   ctx,
		},
		Findings: []Finding{},
	}
}

// Add ajoute un constat en fixant son horodatage s'il est vide.
func (r *Report) Add(f Finding) {
	if f.DetectedAt.IsZero() {
		f.DetectedAt = time.Now().UTC()
	}
	r.Findings = append(r.Findings, f)
}

// Finish clot le rapport et trie les constats pire d'abord.
func (r *Report) Finish() {
	r.Run.FinishedAt = time.Now().UTC()
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Status.rank() != b.Status.rank() {
			return a.Status.rank() > b.Status.rank()
		}
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() > b.Severity.rank()
		}
		return a.ID < b.ID
	})
}

func newRunID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// Bool renvoie un pointeur vers b, pour renseigner le champ Declared.
func Bool(b bool) *bool { return &b }
