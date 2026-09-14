//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Ce fichier regroupe les endroits où la console doit parler à Windows
// directement.

// --- résolution d'écran ----------------------------------------------------

// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, passé comme une poignée valant -4.
const contexteParEcranV2 = ^uintptr(3)

// declarerConscienceResolution annonce à Windows que l'application dessine
// elle-même à la bonne échelle.
//
// Sans cette déclaration, Windows agrandit l'image d'une application prévue
// pour 96 points par pouce, ce qui la rend floue sur tout écran à densité
// élevée. L'appel doit précéder la création de la moindre fenêtre: après,
// Windows a déjà décidé de l'échelle et refuse d'en changer.
func declarerConscienceResolution() {
	user32 := syscall.NewLazyDLL("user32.dll")
	user32.NewProc("SetProcessDpiAwarenessContext").Call(contexteParEcranV2)
}

// --- fenêtres de console ---------------------------------------------------

const creerSansFenetre = 0x08000000 // CREATE_NO_WINDOW

// masquerFenetre empêche l'apparition d'une console derrière l'application.
func masquerFenetre(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: creerSansFenetre,
	}
}

// --- élévation -------------------------------------------------------------

const (
	masqueGarderProcessus = 0x00000040 // SEE_MASK_NOCLOSEPROCESS
	masqueSansAsync       = 0x00000100 // SEE_MASK_NOASYNC
	fenetreMasquee        = 0          // SW_HIDE
	attenteCourte         = 200        // millisecondes
)

type infoExecution struct {
	taille       uint32
	masque       uint32
	fenetre      syscall.Handle
	verbe        *uint16
	fichier      *uint16
	parametres   *uint16
	repertoire   *uint16
	affichage    int32
	instance     syscall.Handle
	listeID      uintptr
	classe       *uint16
	cleClasse    syscall.Handle
	toucheRapide uint32
	icone        syscall.Handle
	processus    syscall.Handle
}

// analyseElevee lance l'analyse avec les privilèges administrateur et suit sa
// progression par un fichier.
//
// Le détour par un fichier de commandes n'est pas une coquetterie: ShellExecuteEx
// est le seul moyen propre d'obtenir l'élévation, et il ne sait pas rediriger
// la sortie d'un programme. Un fichier de commandes, lui, le fait nativement.
// C'est ce qui permet de montrer ce que l'analyse examine au lieu d'afficher
// une attente aveugle.
func analyseElevee(binaire string, args []string, suivi *Analyse) error {
	travail, err := os.MkdirTemp("", "argus-analyse-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(travail)

	progression := filepath.Join(travail, "progression.txt")
	commandes := filepath.Join(travail, "analyse.cmd")

	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString(`"` + binaire + `"`)
	for _, a := range args {
		b.WriteString(` "` + a + `"`)
	}
	b.WriteString(` >nul 2>"` + progression + `"` + "\r\n")
	if err := os.WriteFile(commandes, []byte(b.String()), 0o600); err != nil {
		return err
	}

	poignee, err := executerEleve(commandes)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(poignee)

	// L'identifiant du processus est retenu pour pouvoir l'arrêter. Sans lui,
	// "abandonner" ne ferait que cesser d'attendre pendant que la machine
	// continue d'être parcourue.
	suivi.mu.Lock()
	suivi.pidEleve = identifiantProcessus(poignee)
	suivi.mu.Unlock()

	// On suit le fichier pendant que l'analyse tourne, plutôt que de le lire à
	// la fin: c'est tout l'intérêt.
	go suivreProgression(progression, suivi)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attendre := kernel32.NewProc("WaitForSingleObject")
	for {
		if suivi.estAnnulee() {
			// Un programme ordinaire n'a pas le droit d'arrêter un programme
			// administrateur. On cesse d'attendre; le rapport éventuellement
			// produit sera supprimé par l'appelant.
			return nil
		}
		r, _, _ := attendre.Call(uintptr(poignee), uintptr(attenteCourte))
		if r != 0x00000102 { // WAIT_TIMEOUT
			return nil
		}
	}
}

// executerEleve demande les privilèges administrateur pour un seul processus.
//
// L'appel passe par ShellExecuteEx, l'interface que Windows expose pour cela,
// plutôt que par PowerShell. La version précédente lançait un interpréteur qui
// lançait lui-même la commande élevée: elle ouvrait une fenêtre bien visible et
// la demande d'autorisation se perdait parfois derrière l'application.
func executerEleve(fichier string) (syscall.Handle, error) {
	verbe, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	cible, err := syscall.UTF16PtrFromString(fichier)
	if err != nil {
		return 0, err
	}
	repertoire, err := syscall.UTF16PtrFromString(filepath.Dir(fichier))
	if err != nil {
		return 0, err
	}

	info := infoExecution{
		masque:     masqueGarderProcessus | masqueSansAsync,
		verbe:      verbe,
		fichier:    cible,
		repertoire: repertoire,
		affichage:  fenetreMasquee,
	}
	info.taille = uint32(unsafe.Sizeof(info))

	shell32 := syscall.NewLazyDLL("shell32.dll")
	ret, _, errno := shell32.NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		// 1223 est ERROR_CANCELLED: l'utilisateur a refusé. Ce n'est pas une
		// panne, c'est une décision, et le message doit le dire.
		if e, ok := errno.(syscall.Errno); ok && e == 1223 {
			return 0, fmt.Errorf("l'autorisation administrateur a été refusée")
		}
		return 0, fmt.Errorf("la demande d'élévation a échoué: %v", errno)
	}
	if info.processus == 0 {
		return 0, fmt.Errorf("le processus élevé n'a pas pu être suivi")
	}
	return info.processus, nil
}

// suivreProgression lit le fichier au fur et à mesure qu'il se remplit.
func suivreProgression(chemin string, suivi *Analyse) {
	for i := 0; i < 3000; i++ {
		if suivi.estAnnulee() {
			return
		}
		if b, err := os.ReadFile(chemin); err == nil {
			s := bufio.NewScanner(strings.NewReader(string(b)))
			dernier := ""
			for s.Scan() {
				if nom := extraireEtape(s.Text()); nom != "" {
					dernier = nom
				}
			}
			if dernier != "" {
				suivi.noter(nomLisible(dernier))
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
}

// identifiantProcessus renvoie le numéro d'un processus à partir de sa poignée.
func identifiantProcessus(h syscall.Handle) uint32 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	r, _, _ := kernel32.NewProc("GetProcessId").Call(uintptr(h))
	return uint32(r)
}

// arreterProcessusEleve arrête un processus administrateur et sa descendance.
//
// La console tourne en utilisateur ordinaire et ne peut donc pas arrêter
// elle-même un processus élevé. Elle demande à Windows de le faire à sa place,
// avec les mêmes droits que pour l'avoir lancé, d'où une seconde demande
// d'autorisation. C'est le prix d'un abandon qui abandonne vraiment.
//
// L'option de terminaison en arbre est indispensable: le processus suivi est le
// fichier de commandes, et c'est son enfant qui parcourt la machine. Arrêter
// seulement le parent laisserait l'analyse se poursuivre.
func arreterProcessusEleve(pid uint32) error {
	if pid == 0 {
		return nil
	}
	verbe, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	fichier, err := syscall.UTF16PtrFromString("taskkill.exe")
	if err != nil {
		return err
	}
	args, err := syscall.UTF16PtrFromString(fmt.Sprintf("/PID %d /T /F", pid))
	if err != nil {
		return err
	}

	info := infoExecution{
		masque:     masqueGarderProcessus | masqueSansAsync,
		verbe:      verbe,
		fichier:    fichier,
		parametres: args,
		affichage:  fenetreMasquee,
	}
	info.taille = uint32(unsafe.Sizeof(info))

	shell32 := syscall.NewLazyDLL("shell32.dll")
	ret, _, errno := shell32.NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return fmt.Errorf("l'arrêt de l'analyse n'a pas été autorisé: %v", errno)
	}
	if info.processus != 0 {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		kernel32.NewProc("WaitForSingleObject").Call(uintptr(info.processus), 5000)
		syscall.CloseHandle(info.processus)
	}
	return nil
}

// ouvrirCible demande au shell d'ouvrir une adresse, une console ou un
// programme.
//
// Une seule voie pour les trois, parce que le shell les traite de la même
// façon: une adresse ms-settings, un fichier .msc et un exécutable passent
// tous par la même commande. Écrire trois cas particuliers reviendrait à
// réimplémenter ce que Windows fait déjà.
func ouvrirCible(cible string) error {
	cmd := exec.Command("cmd.exe", "/c", "start", "", cible)
	masquerFenetre(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("impossible d'ouvrir %s: %w", cible, err)
	}
	// On n'attend pas la fin: l'écran ouvert reste affiché tant que
	// l'utilisateur le veut, et la console n'a pas à rester bloquée derrière.
	go cmd.Wait()
	return nil
}

// selectionnerDansExplorateur ouvre le dossier d'un fichier en le
// présélectionnant, plutôt que d'ouvrir le dossier seul: sur un répertoire qui
// contient cent entrées, retrouver la bonne est justement le travail qu'on
// voulait éviter.
func selectionnerDansExplorateur(chemin string) error {
	cmd := exec.Command("explorer.exe", "/select,"+chemin)
	// L'Explorateur renvoie un code non nul même quand il réussit; on ne le
	// consulte donc pas, et l'existence du fichier a déjà été vérifiée.
	_ = cmd.Start()
	go cmd.Wait()
	return nil
}

// lancerProgramme démarre un programme avec un argument, sans attendre sa fin.
//
// Le passage par le shell ne conviendrait pas ici: une adresse interne de
// navigateur comme chrome://extensions n'est pas un protocole que Windows sait
// ouvrir, c'est un argument que seul le navigateur comprend.
func lancerProgramme(chemin string, args ...string) error {
	cmd := exec.Command(chemin, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("impossible de lancer %s: %w", filepath.Base(chemin), err)
	}
	go cmd.Wait()
	return nil
}

// prendreReferenceElevee enregistre la référence d'intégrité avec les
// privilèges administrateur.
//
// Certains fichiers surveillés ne sont lisibles qu'ainsi. Une référence prise
// sans ces droits en omettrait une partie, et l'omission ne se verrait pas:
// les fichiers absents de la référence ne sont simplement jamais comparés.
func prendreReferenceElevee(binaire, reference string) error {
	travail, err := os.MkdirTemp("", "argus-reference-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(travail)

	commandes := filepath.Join(travail, "reference.cmd")
	contenu := "@echo off\r\n" + `"` + binaire + `" baseline --baseline "` + reference + `" >nul 2>&1` + "\r\n"
	if err := os.WriteFile(commandes, []byte(contenu), 0o600); err != nil {
		return err
	}

	poignee, err := executerEleve(commandes)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(poignee)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("WaitForSingleObject").Call(uintptr(poignee), 120000)
	return nil
}
