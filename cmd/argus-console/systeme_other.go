//go:build !windows

package main

import (
	"fmt"
	"os/exec"
)

// La console vise Windows. Ces implantations vides existent pour que le module
// compile ailleurs, ce qui garde la vérification croisée utile: une faute de
// frappe se voit alors sans avoir à construire l'interface entière.

func declarerConscienceResolution() {}

func masquerFenetre(cmd *exec.Cmd) {}

func analyseElevee(binaire string, args []string, suivi *Analyse) error {
	return fmt.Errorf("l'élévation n'est disponible que sous Windows")
}

func arreterProcessusEleve(pid uint32) error { return nil }

func ouvrirCible(cible string) error {
	return fmt.Errorf("l'ouverture des réglages n'est disponible que sous Windows")
}

func selectionnerDansExplorateur(chemin string) error {
	return fmt.Errorf("l'Explorateur n'est disponible que sous Windows")
}

func lancerProgramme(chemin string, args ...string) error {
	return fmt.Errorf("non disponible sur ce système")
}

func prendreReferenceElevee(binaire, reference string) error {
	return fmt.Errorf("l'élévation n'est disponible que sous Windows")
}
