package main

import (
	"io/fs"
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

// dossierDonnees renvoie l'emplacement des données de la console.
//
// Le profil de l'utilisateur, et rien d'autre. La première version essayait
// d'abord ProgramData et retombait sur le profil quand elle n'y avait pas
// accès. Cela paraissait accommodant et se révélait faux: le droit d'écrire
// dans ProgramData dépend des privilèges du moment, donc de la façon dont la
// console a été lancée. Démarrée depuis une console administrateur elle y
// écrivait, démarrée par l'Explorateur elle écrivait ailleurs, et l'historique
// semblait disparaître d'une fois sur l'autre.
//
// Un emplacement qui dépend du contexte d'exécution n'est pas un emplacement.
// Le profil de l'utilisateur est accessible en écriture dans tous les cas, y
// compris depuis un processus élevé.
func dossierDonnees() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dossier := filepath.Join(base, "Argus")
	if err := os.MkdirAll(dossier, 0o755); err != nil {
		return "", err
	}
	recupererAncienEmplacement(dossier)
	return dossier, nil
}

// recupererAncienEmplacement rapatrie ce qu'une version précédente avait rangé
// dans ProgramData.
//
// Sans cela, corriger l'emplacement ferait disparaître l'historique et les
// décisions déjà prises, du point de vue de celui qui utilise l'outil. Un
// correctif qui efface des données en silence n'en est pas un.
//
// Rien n'est écrasé: un fichier déjà présent à la nouvelle place fait autorité.
func recupererAncienEmplacement(nouveau string) {
	ancienBase := os.Getenv("ProgramData")
	if ancienBase == "" {
		return
	}
	ancien := filepath.Join(ancienBase, "Argus")
	if ancien == nouveau {
		return
	}
	if fi, err := os.Stat(ancien); err != nil || !fi.IsDir() {
		return
	}

	_ = filepath.WalkDir(ancien, func(chemin string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		relatif, err := filepath.Rel(ancien, chemin)
		if err != nil {
			return nil
		}
		cible := filepath.Join(nouveau, relatif)
		if fichierExiste(cible) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(cible), 0o755); err != nil {
			return nil
		}
		if contenu, err := os.ReadFile(chemin); err == nil {
			_ = os.WriteFile(cible, contenu, 0o644)
		}
		return nil
	})
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
