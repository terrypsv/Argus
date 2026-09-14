package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Les analyses sont conservees en fichiers JSON, un par analyse, plutot que
// dans une base.
//
// Trois raisons. Ce sont exactement les fichiers que comprend `argus diff`, ce
// qui evite de reimplementer la comparaison. Ils se lisent a la main, se
// copient, s'archivent, et survivent a la disparition de la console. Et ils
// n'ajoutent aucune dependance a une application qui en a deja trente.
//
// Une base se justifierait au-dela de quelques milliers d'analyses. A raison
// d'une par semaine, cela laisse de la marge.

func estWindows() bool { return runtime.GOOS == "windows" }

func fichierExiste(chemin string) bool {
	fi, err := os.Stat(chemin)
	return err == nil && !fi.IsDir()
}

// dossierDonnees renvoie l'emplacement des donnees de la console.
//
// ProgramData d'abord, pour qu'une analyse planifiee lancee par le systeme et
// une analyse lancee a la main ecrivent au meme endroit. S'il n'est pas
// accessible en ecriture, faute de privileges, on retombe sur le profil de
// l'utilisateur plutot que d'echouer: mieux vaut un historique personnel
// qu'aucun historique.
func dossierDonnees() (string, error) {
	var base string
	if estWindows() {
		base = os.Getenv("ProgramData")
	}
	if base != "" {
		candidat := filepath.Join(base, "Argus")
		if err := os.MkdirAll(candidat, 0o755); err == nil {
			if accessibleEnEcriture(candidat) {
				return candidat, nil
			}
		}
	}
	perso, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	candidat := filepath.Join(perso, "Argus")
	return candidat, os.MkdirAll(candidat, 0o755)
}

func accessibleEnEcriture(dossier string) bool {
	essai := filepath.Join(dossier, ".essai")
	f, err := os.Create(essai)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(essai)
	return true
}

func dossierAnalyses() (string, error) {
	base, err := dossierDonnees()
	if err != nil {
		return "", err
	}
	dossier := filepath.Join(base, "analyses")
	return dossier, os.MkdirAll(dossier, 0o755)
}

// analysesConservees liste les rapports du plus recent au plus ancien.
//
// Le tri s'appuie sur le nom du fichier, qui porte la date au format
// annee-mois-jour: l'ordre alphabetique est alors l'ordre chronologique. Se
// fier a la date de modification du fichier serait plus fragile, une copie ou
// une restauration la remettant a zero.
func analysesConservees() ([]string, error) {
	dossier, err := dossierAnalyses()
	if err != nil {
		return nil, err
	}
	entrees, err := os.ReadDir(dossier)
	if err != nil {
		return nil, err
	}
	var chemins []string
	for _, e := range entrees {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			chemins = append(chemins, filepath.Join(dossier, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(chemins)))
	return chemins, nil
}

// cheminExceptions et cheminReference désignent les deux fichiers que l'outil
// lit et écrit en dehors des rapports.
//
// La console les impose plutôt que de laisser Argus les chercher. Sans cela,
// ils sont cherchés dans le répertoire courant du processus, qui dépend
// d'où la console a été lancée: assumer un constat écrirait dans un fichier
// qu'une analyse suivante, lancée autrement, ne lirait pas. Le réglage aurait
// l'air de fonctionner et serait perdu.
func cheminExceptions() (string, error) {
	base, err := dossierDonnees()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "argus-exceptions.json"), nil
}

func cheminReference() (string, error) {
	base, err := dossierDonnees()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "argus-baseline.json"), nil
}
