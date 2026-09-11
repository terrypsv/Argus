//go:build !windows

package main

import (
	"fmt"
	"os/exec"
)

// La console vise Windows. Ces implantations vides existent pour que le module
// compile ailleurs, ce qui garde la verification croisee utile: une faute de
// frappe se voit alors sans avoir a construire l'interface entiere.

func declarerConscienceResolution() {}

func masquerFenetre(cmd *exec.Cmd) {}

func lancerEleve(binaire string, args []string) error {
	return fmt.Errorf("l'élévation n'est disponible que sous Windows")
}
