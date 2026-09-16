package report

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Ce test lit les sources des contrôles et vérifie que chaque catégorie qu'ils
// emploient figure dans la table de traduction.
//
// Il existe parce que l'absence ne se voyait pas. categorieFrancaise retombe sur
// la version en majuscules quand elle ne connaît pas une catégorie, ce qui est
// le bon comportement à l'exécution: mieux vaut afficher KERNEL que rien. Mais
// ce repli masque l'oubli, et il a fallu lancer l'outil sur une machine Linux
// pour découvrir que "kernel" n'avait jamais été traduit.
//
// La vérification interroge la table directement plutôt que de comparer le
// résultat à la version en majuscules. Une première version faisait cette
// comparaison et signalait "antivirus" comme absent alors qu'il y figurait: sa
// traduction est simplement identique à son nom. Un test qui accuse à tort est
// pire qu'un test absent, parce qu'on finit par ignorer ce qu'il dit.
//
// Lire le code source depuis un test est inhabituel. La raison est que les
// catégories ne sont enregistrées nulle part: elles sont écrites en clair dans
// chaque appel, et la seule liste exhaustive est le code lui-même. Les énumérer
// à l'exécution demanderait une machine de chaque système.

// Une catégorie se déclare à deux endroits, et les deux sont lus.
//
// L'enregistrement d'un contrôle porte son champ Category, et chaque constat
// répète la catégorie en deuxième argument. Les deux listes coïncident
// aujourd'hui; rien ne garantit qu'elles coïncideront demain, et ne lire que
// l'une reviendrait à valider la table sur la moitié des déclarations.
var motifs = []*regexp.Regexp{
	// Champ de l'enregistrement: {Name: "firewall", Category: "network", ...}
	regexp.MustCompile(`Category:\s*"([a-z][a-z0-9-]*)"`),
	// Deuxième argument de fail, pass, info et errFinding.
	regexp.MustCompile(`(?:fail|pass|info|errFinding)\(\s*"[^"]+",\s*"([a-z][a-z0-9-]*)"`),
	// Les constantes locales du genre: const cat = "integrity"
	regexp.MustCompile(`(?:const|var)?\s*\bcat\b\s*:?=\s*"([a-z][a-z0-9-]*)"`),
}

func TestChaqueCategorieEstTraduite(t *testing.T) {
	fichiers, err := filepath.Glob(filepath.Join("..", "checks", "*.go"))
	if err != nil || len(fichiers) == 0 {
		t.Skip("sources des contrôles introuvables, test sans objet")
	}

	employees := map[string][]string{}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		brut, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src, nom := string(brut), filepath.Base(f)
		for _, motif := range motifs {
			for _, m := range motif.FindAllStringSubmatch(src, -1) {
				if !contient(employees[m[1]], nom) {
					employees[m[1]] = append(employees[m[1]], nom)
				}
			}
		}
	}

	if len(employees) == 0 {
		t.Fatal("aucune catégorie trouvée dans les sources: le motif de reconnaissance est à revoir")
	}

	var manquantes []string
	for cat := range employees {
		if _, connue := categoriesFrancaises[cat]; !connue {
			manquantes = append(manquantes, cat)
		}
	}
	sort.Strings(manquantes)

	for _, cat := range manquantes {
		sort.Strings(employees[cat])
		t.Errorf("la catégorie %q ne figure pas dans categoriesFrancaises (employée dans %s)",
			cat, strings.Join(employees[cat], ", "))
	}
}

// TestAucuneTraductionInutile signale l'inverse: une entrée de la table qui ne
// correspond à aucune catégorie réelle.
//
// Elle ne casse rien, mais elle ment sur ce que l'outil sait faire, et c'est
// exactement ainsi qu'une entrée fautive survit: "processes" a figuré dans la
// table alors que la catégorie s'appelle "process".
func TestAucuneTraductionInutile(t *testing.T) {
	fichiers, err := filepath.Glob(filepath.Join("..", "checks", "*.go"))
	if err != nil || len(fichiers) == 0 {
		t.Skip("sources des contrôles introuvables, test sans objet")
	}

	employees := map[string]bool{}
	for _, f := range fichiers {
		brut, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(brut)
		for _, motif := range motifs {
			for _, m := range motif.FindAllStringSubmatch(src, -1) {
				employees[m[1]] = true
			}
		}
	}

	var inutiles []string
	for cat := range categoriesFrancaises {
		if !employees[cat] {
			inutiles = append(inutiles, cat)
		}
	}
	sort.Strings(inutiles)

	if len(inutiles) > 0 {
		t.Errorf("ces traductions ne correspondent à aucune catégorie employée: %s",
			strings.Join(inutiles, ", "))
	}
}

func contient(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
