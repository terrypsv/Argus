package main

import (
	"fmt"
	"os"
)

// Ce fichier donne à la console un second usage: analyser sans rien afficher.
//
// Il existe pour la tâche planifiée. Faire exécuter la ligne de commande par le
// planificateur ouvrirait une fenêtre noire à chaque analyse, ce qui est
// exactement le genre de détail qui fait qu'on finit par désactiver la
// surveillance. La console est un programme graphique: lancée dans ce mode, elle
// ne crée aucune fenêtre et se termine quand l'analyse est écrite.
//
// Elle n'écrit rien sur la sortie standard, un programme graphique n'en ayant
// pas. En cas d'échec, le code de sortie suffit: le planificateur l'enregistre
// et l'affiche dans sa colonne de résultat.

// modeTache exécute une analyse silencieuse si la ligne de commande le demande,
// et indique si le programme doit s'arrêter là.
func modeTache() (bool, int) {
	demande := false
	for _, a := range os.Args[1:] {
		if a == "--tache" {
			demande = true
			break
		}
	}
	if !demande {
		return false, 0
	}

	app := NouvelleApp(version)
	chemin, err := localiserArgus()
	if err != nil {
		return true, 2
	}
	app.binaire = chemin

	// Les réglages de l'utilisateur sont respectés, y compris le type de
	// machine: une analyse planifiée qui n'appliquerait pas les mêmes règles
	// qu'une analyse lancée à la main produirait des écarts inexplicables entre
	// deux rapports de la même journée.
	r := lireReglages()
	opt := OptionsAnalyse{
		Rapide:          r.AnalyseRapide,
		Eleve:           r.Elevation,
		Profil:          r.Profil,
		VerifierPaquets: r.VerifierPaquets,
	}

	suivi := &Analyse{}
	if _, err := lancerAnalyse(app.binaire, opt, suivi); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return true, 1
	}
	return true, 0
}
