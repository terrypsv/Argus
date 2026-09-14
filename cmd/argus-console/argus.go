package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// localiserArgus trouve la ligne de commande sur cette machine.
//
// Trois endroits, dans cet ordre: à côté de la console, ce qui est le cas après
// une installation normale; dans le PATH, que l'installeur configure; puis le
// répertoire courant, qui sert pendant le développement.
//
// L'ordre compte. Chercher d'abord dans le PATH reviendrait à lancer une
// version d'Argus différente de celle installée avec la console.
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

// Analyse suit une exécution en cours.
//
// Elle existe parce qu'une analyse n'est plus un appel bloquant dont on attend
// le retour: l'utilisateur change d'onglet pendant qu'elle tourne, veut savoir
// où elle en est, et doit pouvoir l'abandonner.
type Analyse struct {
	mu        sync.Mutex
	encours   bool
	etape     string
	debut     time.Time
	annulee   bool
	sortie    string
	processus *exec.Cmd // renseigné seulement sans élévation
	pidEleve  uint32    // renseigné seulement avec élévation
}

func (a *Analyse) etat() (bool, string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := 0
	if a.encours {
		s = int(time.Since(a.debut).Seconds())
	}
	return a.encours, a.etape, s
}

func (a *Analyse) noter(etape string) {
	a.mu.Lock()
	a.etape = etape
	a.mu.Unlock()
}

// annuler abandonne l'analyse en cours, et l'arrête réellement.
//
// Sans élévation, le processus est tué directement. Avec élévation, il ne peut
// pas l'être ainsi: un programme ordinaire n'a pas le droit d'arrêter un
// programme administrateur. On demande donc à Windows de le faire avec les
// mêmes droits que pour le lancer, ce qui vaut une seconde autorisation.
//
// L'alternative aurait été de cesser d'attendre en laissant l'analyse finir
// dans son coin. Cela aurait eu l'air de marcher, alors que la machine aurait
// continué d'être parcourue: "arrêter" doit arrêter.
func (a *Analyse) annuler() {
	a.mu.Lock()
	a.annulee = true
	p := a.processus
	pid := a.pidEleve
	a.mu.Unlock()

	if p != nil && p.Process != nil {
		_ = p.Process.Kill()
	}
	if pid != 0 {
		_ = arreterProcessusEleve(pid)
	}
}

func (a *Analyse) estAnnulee() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.annulee
}

// nomLisible traduit le nom interne d'un contrôle en quelque chose qui se lit.
//
// La ligne de commande annonce "listening-ports" à un opérateur qui sait ce que
// c'est. Dans une fenêtre destinée à quelqu'un qui ne connaît pas la ligne de
// commande, ce nom ne veut rien dire et inquiète plus qu'il n'informe.
func nomLisible(interne string) string {
	noms := map[string]string{
		"system-info":        "informations système",
		"privilege":          "niveau de privilèges",
		"file-integrity":     "intégrité des fichiers critiques",
		"browser-extensions": "extensions de navigateur",
		"defender":           "antivirus",
		"firewall":           "pare-feu",
		"uac":                "contrôle de compte d'utilisateur",
		"smb1":               "partage de fichiers ancien",
		"rdp":                "bureau à distance",
		"bitlocker":          "chiffrement du disque",
		"disk-usage":         "occupation des disques",
		"listening-ports":    "ports ouverts sur le réseau",
		"startup":            "programmes lancés au démarrage",
		"scheduled-tasks":    "tâches planifiées",
		"local-admins":       "comptes administrateurs",
		"root-certificates":  "certificats de confiance",
		"kernel-hardening":   "durcissement du noyau",
		"kernel-taint":       "intégrité du noyau",
		"ld-preload":         "détournement de bibliothèques",
		"accounts":           "comptes locaux",
		"ssh-hardening":      "configuration SSH",
		"suid":               "binaires à privilèges",
		"world-writable":     "fichiers modifiables par tous",
		"mount-flags":        "options de montage",
		"cron-persistence":   "tâches récurrentes",
		"systemd-persistence": "services système",
		"process-anomalies":  "processus en cours",
		"package-verify":     "empreintes de la distribution",
		"sip":                "protection de l'intégrité système",
		"gatekeeper":         "contrôle des applications",
		"filevault":          "chiffrement du disque",
		"launch-agents":      "éléments de démarrage",
		"kernel-extensions":  "extensions du noyau",
		"system-extensions":  "extensions système",
		"remote-access":      "accès distant",
		"system-integrity":   "intégrité du système",
	}
	if n, ok := noms[interne]; ok {
		return n
	}
	return interne
}

// lancerAnalyse exécute une analyse et renvoie le chemin du rapport produit.
//
// La progression est lue au fil de l'eau. Sans élévation, elle arrive par la
// sortie d'erreur du processus; avec élévation, celui-ci est un processus
// séparé dont on ne peut rien lire, alors il écrit dans un fichier que l'on
// suit. Le détour par un fichier de commandes sert uniquement à cela: c'est le
// seul moyen de rediriger la sortie d'un programme lancé en administrateur.
func lancerAnalyse(binaire string, opt OptionsAnalyse, suivi *Analyse) (string, error) {
	dossier, err := dossierAnalyses()
	if err != nil {
		return "", err
	}
	horodatage := time.Now().Format("2006-01-02T15-04-05")
	sortie := filepath.Join(dossier, horodatage+".json")

	suivi.mu.Lock()
	suivi.sortie = sortie
	suivi.mu.Unlock()

	args := []string{"scan", "--json", sortie, "--no-color"}
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
		err = analyseElevee(binaire, args, suivi)
	} else {
		err = analyseOrdinaire(binaire, args, suivi)
	}

	if suivi.estAnnulee() {
		// Une analyse abandonnée ne doit rien laisser derrière elle, y compris
		// si le processus a eu le temps d'écrire avant de s'arrêter.
		os.Remove(sortie)
		return "", fmt.Errorf("analyse abandonnée")
	}
	if err != nil {
		os.Remove(sortie)
		return "", err
	}
	if !fichierExiste(sortie) {
		return "", fmt.Errorf("l'analyse s'est terminée sans produire de rapport")
	}
	return sortie, nil
}

// analyseOrdinaire lance l'analyse sans élévation et lit sa progression
// directement sur sa sortie d'erreur.
func analyseOrdinaire(binaire string, args []string, suivi *Analyse) error {
	cmd := exec.Command(binaire, args...)
	masquerFenetre(cmd)

	flux, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	suivi.mu.Lock()
	suivi.processus = cmd
	suivi.mu.Unlock()

	lecteur := bufio.NewScanner(flux)
	for lecteur.Scan() {
		if nom := extraireEtape(lecteur.Text()); nom != "" {
			suivi.noter(nomLisible(nom))
		}
	}
	// Les codes 2, 3 et 4 signalent un seuil franchi, pas une panne: le rapport
	// existe et doit être lu. L'appelant vérifie sa présence.
	_ = cmd.Wait()
	return nil
}

// extraireEtape reconnaît une ligne de progression.
//
// La ligne a la forme "  ... nom-du-controle", le préfixe étant décoratif. On
// ne garde que ce qui suit, et rien d'autre: les messages d'avertissement
// passent par le même canal et ne doivent pas être pris pour des étapes.
func extraireEtape(ligne string) string {
	l := strings.TrimSpace(ligne)
	for _, prefixe := range []string{"\u2026", "..."} {
		if strings.HasPrefix(l, prefixe) {
			nom := strings.TrimSpace(strings.TrimPrefix(l, prefixe))
			if nom != "" && !strings.Contains(nom, " ") {
				return nom
			}
		}
	}
	return ""
}
