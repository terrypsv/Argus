package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Les structures ci-dessous decrivent le rapport JSON produit par la ligne de
// commande. Elles sont volontairement redeclarees plutot qu'importees du
// paquet model.
//
// Importer les types internes ferait de la console un morceau du moteur, et
// tout remaniement interne la casserait. Ici, le contrat est la sortie
// publiee, celle que n'importe quel autre programme peut lire.

// Bulletin est une analyse complete.
type Bulletin struct {
	Outil        string             `json:"tool"`
	Version      string             `json:"version"`
	Machine      Machine            `json:"host"`
	Debut        time.Time          `json:"started_at"`
	Fin          time.Time          `json:"finished_at"`
	DureeMS      int64              `json:"duration_ms"`
	Note         int                `json:"score"`
	Mention      string             `json:"grade"`
	Durcissement Axe                `json:"hardening"`
	Integrite    Axe                `json:"integrity"`
	Verdict      string             `json:"verdict"`
	Profil       string             `json:"profile"`
	Constats     []Constat          `json:"findings"`
	Comptes      map[string]int     `json:"counts"`
	Poids        map[string]float64 `json:"weights"`
}

// Machine identifie le poste analyse.
type Machine struct {
	Nom        string `json:"hostname"`
	Systeme    string `json:"os"`
	Arch       string `json:"arch"`
	Noyau      string `json:"kernel"`
	Plateforme string `json:"platform"`
	Coeurs     int    `json:"num_cpu"`
}

// Axe est le resultat d'une des deux notes.
//
// NoteBrute est celle qu'aurait la machine sans aucune exception. Les deux sont
// publiees ensemble pour qu'une derogation ne puisse pas se faire passer pour
// une correction.
type Axe struct {
	Note         int    `json:"score"`
	Mention      string `json:"grade"`
	Ecarts       int    `json:"issues"`
	NoteBrute    int    `json:"raw_score"`
	MentionBrute string `json:"raw_grade"`
	Acceptes     int    `json:"accepted"`
}

// Constat est un point releve par un controle.
type Constat struct {
	ID          string   `json:"id"`
	Categorie   string   `json:"category"`
	Titre       string   `json:"title"`
	Gravite     string   `json:"severity"`
	Reussi      bool     `json:"passed"`
	Detail      string   `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Preuves     []string `json:"evidence,omitempty"`
	Accepte     string   `json:"accepted,omitempty"`
	ComptePar   string   `json:"superseded,omitempty"`
	Erreur      string   `json:"error,omitempty"`
}

// Ouvert indique si le constat est un ecart a traiter: ni reussi, ni purement
// informatif, ni assume sciemment.
func (c Constat) Ouvert() bool {
	return !c.Reussi && c.Gravite != "INFO" && c.Accepte == ""
}

// lireBulletin charge un rapport depuis le disque.
func lireBulletin(chemin string) (*Bulletin, error) {
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	var b Bulletin
	if err := json.Unmarshal(brut, &b); err != nil {
		return nil, fmt.Errorf("%s n'est pas un rapport Argus lisible: %w", chemin, err)
	}
	if b.Outil != "Argus" {
		return nil, fmt.Errorf("%s n'a pas été produit par Argus", chemin)
	}
	return &b, nil
}
