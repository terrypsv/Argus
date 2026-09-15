package main

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

// EtatReference décrit la photographie d'intégrité et ce qu'elle vaut
// aujourd'hui.
//
// Deux informations comptent et sont souvent confondues: la date à laquelle la
// référence a été prise, et le nombre de fichiers qui s'en écartent depuis. La
// première dit ce qu'elle décrit, la seconde ce qu'elle a détecté.
type EtatReference struct {
	Existe      bool      `json:"existe"`
	Chemin      string    `json:"chemin"`
	PriseLe     time.Time `json:"priseLe"`
	Algorithme  string    `json:"algorithme"`
	Fichiers    int       `json:"fichiers"`
	Liste       []string  `json:"liste"`
	Alteres     int       `json:"alteres"`
	MisAJour    int       `json:"misAJour"`
	Changes     int       `json:"changes"`
	Manquants   int       `json:"manquants"`
	Compare     bool      `json:"compare"`
}

// referenceSurDisque est la forme du fichier écrit par `argus baseline`.
type referenceSurDisque struct {
	CreeLe     time.Time         `json:"created_at"`
	Algorithme string            `json:"algorithm"`
	Fichiers   map[string]string `json:"files"`
}

// LaReference renseigne l'écran dédié.
//
// Les compteurs d'écarts viennent de la dernière analyse et non d'un calcul
// fait ici: refaire les empreintes serait long, et surtout produirait un
// résultat qui pourrait différer de celui affiché ailleurs dans la console.
func (a *App) LaReference() (*EtatReference, error) {
	e := &EtatReference{}

	chemin, err := cheminReference()
	if err != nil {
		return e, nil
	}
	e.Chemin = chemin

	brut, err := os.ReadFile(chemin)
	if err != nil {
		return e, nil
	}
	var r referenceSurDisque
	if err := json.Unmarshal(brut, &r); err != nil {
		return e, nil
	}

	e.Existe = true
	e.PriseLe = r.CreeLe
	e.Algorithme = r.Algorithme
	e.Fichiers = len(r.Fichiers)
	for f := range r.Fichiers {
		e.Liste = append(e.Liste, f)
	}
	sort.Strings(e.Liste)

	b, err := a.DernierBulletin()
	if err != nil || b == nil {
		return e, nil
	}
	e.Compare = true
	for _, c := range b.Constats {
		if c.Reussi {
			continue
		}
		n := len(c.Preuves)
		switch c.ID {
		case "INTEG-TAMPERED":
			e.Alteres = n
		case "INTEG-UPDATED":
			e.MisAJour = n
		case "INTEG-CHANGED":
			e.Changes = n
		case "INTEG-MISSING":
			e.Manquants = n
		}
	}
	return e, nil
}
