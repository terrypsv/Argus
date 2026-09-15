package main

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

// Les exceptions sont lues dans le fichier qu'écrit la ligne de commande, tel
// qu'il est: des dates au format jour, et rien d'autre que l'identifiant du
// constat.
//
// Les dates sont conservées en chaînes plutôt qu'en horodatages. Le fichier
// écrit "2026-09-15", pas un instant précis avec son fuseau, et prétendre le
// contraire ferait échouer la lecture en silence: tous les champs
// apparaîtraient vides sans qu'aucune erreur ne soit levée.

// Exception est un constat assumé, enrichi de ce que la dernière analyse en
// sait.
//
// Le fichier ne contient qu'un identifiant. Afficher "DISK-LOW-C" à quelqu'un
// qui a assumé ce constat il y a trois mois ne lui rappellera rien: le titre et
// la gravité sont repris de l'analyse la plus récente.
type Exception struct {
	ID     string `json:"id"`
	Motif  string `json:"reason"`
	Par    string `json:"accepted_by"`
	Le     string `json:"accepted_at"`
	Expire string `json:"expires"`

	Titre         string `json:"titre,omitempty"`
	Gravite       string `json:"gravite,omitempty"`
	Connu         bool   `json:"connu"`
	SansEcheance  bool   `json:"sansEcheance"`
	Expiree       bool   `json:"expiree"`
	JoursRestants int    `json:"joursRestants"`
}

type fichierExceptions struct {
	Exceptions []Exception `json:"exceptions"`
}

// LesExceptions renvoie ce qui est porté sciemment.
func (a *App) LesExceptions() ([]Exception, error) {
	chemin, err := cheminExceptions()
	if err != nil {
		return nil, err
	}
	brut, err := os.ReadFile(chemin)
	if err != nil {
		// Aucun fichier signifie aucune exception, ce qui est l'état normal
		// d'une machine dont on n'a encore rien assumé.
		return []Exception{}, nil
	}

	var f fichierExceptions
	if err := json.Unmarshal(brut, &f); err != nil {
		return nil, err
	}

	// La dernière analyse fournit le titre et la gravité. Son absence n'est pas
	// bloquante: on affiche alors l'identifiant seul plutôt que rien.
	titres := map[string]Constat{}
	if b, err := a.DernierBulletin(); err == nil && b != nil {
		for _, c := range b.Constats {
			titres[c.ID] = c
		}
	}

	aujourdhui := time.Now().Truncate(24 * time.Hour)
	for i := range f.Exceptions {
		e := &f.Exceptions[i]
		if c, ok := titres[e.ID]; ok {
			e.Titre = c.Titre
			e.Gravite = c.Gravite
			e.Connu = true
		}
		if e.Expire == "" {
			e.SansEcheance = true
			continue
		}
		fin, err := time.Parse("2006-01-02", e.Expire)
		if err != nil {
			e.SansEcheance = true
			continue
		}
		e.JoursRestants = int(fin.Sub(aujourdhui).Hours() / 24)
		e.Expiree = e.JoursRestants < 0
	}

	// Ce qui expire le plus tôt en premier: c'est ce sur quoi il faudra
	// revenir. Les exceptions sans échéance ferment la marche, puisqu'elles
	// n'appellent aucune décision datée.
	sort.SliceStable(f.Exceptions, func(i, j int) bool {
		a, b := f.Exceptions[i], f.Exceptions[j]
		if a.SansEcheance != b.SansEcheance {
			return !a.SansEcheance
		}
		return a.JoursRestants < b.JoursRestants
	})
	return f.Exceptions, nil
}
