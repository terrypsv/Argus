package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// La comparaison n'est pas recalculée ici: elle est demandée à la ligne de
// commande, qui sait déjà la faire, et lue au format qu'elle publie.
//
// La refaire côté console aurait été plus direct à écrire et faux à terme: deux
// implantations d'une même règle finissent par ne plus dire la même chose de la
// même machine, et le jour où elles divergent, aucune des deux n'est croyable.

// Changement est une différence entre deux analyses.
type Changement struct {
	Genre     string `json:"kind"`
	ID        string `json:"id"`
	Categorie string `json:"category"`
	Titre     string `json:"title"`
	Gravite   string `json:"severity"`
	Ligne     string `json:"line,omitempty"`
	Alarmant  bool   `json:"alarming"`
}

// Comparaison est le résultat complet, tel que la ligne de commande le publie.
type Comparaison struct {
	Machine           string       `json:"host"`
	Avant             time.Time    `json:"before"`
	Apres             time.Time    `json:"after"`
	DurcissementAvant int          `json:"hardening_before"`
	DurcissementApres int          `json:"hardening_after"`
	IntegriteAvant    int          `json:"integrity_before"`
	IntegriteApres    int          `json:"integrity_after"`
	Alarmants         int          `json:"alarming"`
	Changements       []Changement `json:"changes"`
}

// Changements compare les deux analyses les plus récentes.
//
// Moins de deux analyses n'est pas une erreur: c'est l'état normal au premier
// lancement, et l'interface doit le présenter comme tel plutôt que d'afficher
// un message d'échec pour une situation parfaitement normale.
func (a *App) Changements() (*Comparaison, error) {
	chemins, err := analysesConservees()
	if err != nil || len(chemins) < 2 {
		return nil, nil
	}
	// analysesConservees trie du plus récent au plus ancien.
	return a.ComparerAnalyses(chemins[1], chemins[0])
}

// ComparerAnalyses confronte deux analyses conservées.
func (a *App) ComparerAnalyses(avant, apres string) (*Comparaison, error) {
	if a.binaire == "" {
		return nil, fmt.Errorf("le programme argus est introuvable sur cette machine")
	}

	f, err := os.CreateTemp("", "argus-comparaison-*.json")
	if err != nil {
		return nil, err
	}
	chemin := f.Name()
	f.Close()
	defer os.Remove(chemin)

	if _, err := executerCommande(a.binaire, "diff", avant, apres, "--json", chemin); err != nil {
		return nil, err
	}

	brut, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	var c Comparaison
	if err := json.Unmarshal(brut, &c); err != nil {
		return nil, fmt.Errorf("la comparaison n'a pas pu être lue: %w", err)
	}
	return &c, nil
}
