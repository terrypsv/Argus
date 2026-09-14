package report

import (
	"encoding/json"
	"io"
	"time"
)

// La comparaison existe en deux rendus: un texte pour le terminal, et ce
// format pour tout programme qui veut s'en servir.
//
// Il a été ajouté parce que la console de bureau devait afficher les
// changements avec des boutons plutôt qu'un bloc de texte. La solution
// paresseuse aurait été de recoder la comparaison de son côté; il y aurait
// alors eu deux implémentations, qui auraient fini par ne plus dire la même
// chose de la même machine.
//
// Les deux rapports comparés ne sont pas inclus: ils pèsent plusieurs centaines
// de kilooctets chacun, et celui qui demande une comparaison les a déjà.

type changementJSON struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Line     string `json:"line,omitempty"`
	Alarming bool   `json:"alarming"`
}

type diffJSON struct {
	Host            string           `json:"host"`
	Before          time.Time        `json:"before"`
	After           time.Time        `json:"after"`
	HardeningBefore int              `json:"hardening_before"`
	HardeningAfter  int              `json:"hardening_after"`
	IntegrityBefore int              `json:"integrity_before"`
	IntegrityAfter  int              `json:"integrity_after"`
	Alarming        int              `json:"alarming"`
	Changes         []changementJSON `json:"changes"`
}

// JSONDiff écrit une comparaison au format JSON.
//
// La gravité est rendue en toutes lettres plutôt qu'en nombre: un consommateur
// extérieur n'a aucune raison de connaître l'ordre interne des niveaux, et un
// entier changerait de sens le jour où un niveau serait inséré.
func JSONDiff(w io.Writer, d Diff) error {
	sortie := diffJSON{
		Host:            d.New.Host.Hostname,
		Before:          d.Old.FinishedAt,
		After:           d.New.FinishedAt,
		HardeningBefore: d.Old.Hardening.Score,
		HardeningAfter:  d.New.Hardening.Score,
		IntegrityBefore: d.Old.Integrity.Score,
		IntegrityAfter:  d.New.Integrity.Score,
		Alarming:        d.Alarming,
		Changes:         make([]changementJSON, 0, len(d.Changes)),
	}
	for _, c := range d.Changes {
		sortie.Changes = append(sortie.Changes, changementJSON{
			Kind:     c.Kind,
			ID:       c.ID,
			Category: c.Category,
			Title:    c.Title,
			Severity: c.Severity.String(),
			Line:     c.Line,
			Alarming: c.Alarming,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sortie)
}
