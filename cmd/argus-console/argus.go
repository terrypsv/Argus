package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// localiserArgus trouve la ligne de commande sur cette machine.
//
// Trois endroits, dans cet ordre: à côté de la console, ce qui est le cas après
// une installation normale; dans le PATH, que l'installeur configure; puis le
// répertoire courant, qui sert pendant le développement.
//
// L'ordre compte. Chercher d'abord dans le PATH reviendrait à lancer une
// version d'Argus différente de celle installée avec la console, et à afficher
// des résultats produits par un moteur que l'utilisateur croit connaître.
func localiserArgus() (string, error) {
	nom := "argus"
	if estWindows() {
		nom = "argus.exe"
	}

	if propre, err := os.Executable(); err == nil {
		candidat := filepath.Join(filepath.Dir(propre), nom)
		if fichierExiste(candidat) {
			return candidat, nil
		}
	}
	if chemin, err := exec.LookPath(nom); err == nil {
		return chemin, nil
	}
	if fichierExiste(nom) {
		return filepath.Abs(nom)
	}
	return "", fmt.Errorf("le programme %s est introuvable, ni à côté de la console ni dans le PATH", nom)
}

// lancerAnalyse exécute une analyse et renvoie le chemin du rapport produit.
//
// Le rapport passe par un fichier plutôt que par la sortie standard, et ce
// détail rend l'élévation possible: un processus lancé avec les privilèges
// administrateur est un processus distinct, dont on ne peut pas lire la sortie.
// Un fichier, si.
func lancerAnalyse(binaire string, opt OptionsAnalyse) (string, error) {
	dossier, err := dossierAnalyses()
	if err != nil {
		return "", err
	}
	sortie := filepath.Join(dossier, time.Now().Format("2006-01-02T15-04-05")+".json")

	args := []string{"scan", "--json", sortie, "--quiet", "--no-color"}
	// L'analyse rapide saute les parcours de disque, qui n'existent que sous
	// Linux et macOS. La proposer ailleurs serait promettre un gain nul.
	if opt.Rapide && runtime.GOOS != "windows" {
		args = append(args, "--quick")
	}
	if opt.Profil != "" && opt.Profil != "workstation" {
		args = append(args, "--profile", opt.Profil)
	}
	if opt.VerifierPaquets && runtime.GOOS == "linux" {
		args = append(args, "--verify-packages")
	}

	if opt.Eleve && estWindows() {
		if err := lancerEleve(binaire, args); err != nil {
			return "", err
		}
	} else {
		cmd := exec.Command(binaire, args...)
		masquerFenetre(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Les codes 2, 3 et 4 signalent un seuil franchi, pas une panne: le
			// rapport existe et doit être lu. Seule l'absence de fichier est
			// une vraie erreur.
			if !fichierExiste(sortie) {
				return "", fmt.Errorf("l'analyse a échoué: %v\n%s", err, strings.TrimSpace(string(out)))
			}
		}
	}

	if !fichierExiste(sortie) {
		return "", fmt.Errorf("l'analyse s'est terminée sans produire de rapport")
	}
	return sortie, nil
}
