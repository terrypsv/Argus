package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Les réglages sont conservés à côté des analyses, dans un fichier lisible.
//
// Ils ne vont pas dans le registre, et ce n'est pas un détail d'implantation:
// un réglage qu'on ne peut ni lire, ni copier, ni sauvegarder avec le reste de
// ses données finit par être un réglage qu'on refait à chaque installation.

// Reglages porte ce que l'utilisateur a choisi et que la console doit retenir.
type Reglages struct {
	// Analyse
	Profil          string `json:"profil"`
	AnalyseRapide   bool   `json:"analyseRapide"`
	Elevation       bool   `json:"elevation"`
	VerifierPaquets bool   `json:"verifierPaquets"`

	// Conservation. Zéro signifie sans limite: une machine analysée une fois
	// par semaine accumule cinquante-deux fichiers par an, ce qui ne justifie
	// pas d'effacer quoi que ce soit par défaut.
	JoursConserves int `json:"joursConserves"`
}

// reglagesParDefaut décrit le comportement d'une console qui n'a jamais été
// réglée. L'élévation est demandée par défaut parce qu'une analyse partielle
// qui ne le dit pas assez fort vaut moins qu'une autorisation à donner.
func reglagesParDefaut() Reglages {
	return Reglages{
		Profil:         "workstation",
		AnalyseRapide:  false,
		Elevation:      true,
		JoursConserves: 0,
	}
}

func cheminReglages() (string, error) {
	base, err := dossierDonnees()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "reglages.json"), nil
}

// lireReglages charge les réglages, ou renvoie les valeurs par défaut.
//
// Un fichier absent ou illisible ne fait pas échouer la console: elle repart
// des valeurs par défaut. Refuser de démarrer parce qu'un fichier de confort
// est abîmé serait disproportionné.
func lireReglages() Reglages {
	r := reglagesParDefaut()
	chemin, err := cheminReglages()
	if err != nil {
		return r
	}
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return r
	}
	_ = json.Unmarshal(brut, &r)
	if r.Profil == "" {
		r.Profil = "workstation"
	}
	return r
}

func ecrireReglages(r Reglages) error {
	chemin, err := cheminReglages()
	if err != nil {
		return err
	}
	brut, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(chemin, append(brut, '\n'), 0o644)
}
