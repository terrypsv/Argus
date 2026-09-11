//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// Ce fichier regroupe les trois endroits ou la console doit parler a Windows
// directement. Chacun corrige un defaut qui se voyait a l'usage.

// --- resolution d'ecran ----------------------------------------------------

// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, passe comme une poignee valant -4.
const contexteParEcranV2 = ^uintptr(3) // equivaut a (HANDLE)-4

// declarerConscienceResolution annonce a Windows que l'application dessine
// elle-meme a la bonne echelle.
//
// Sans cette declaration, Windows agrandit l'image d'une application prevue
// pour 96 points par pouce, ce qui la rend floue sur tout ecran a densite
// elevee. C'est le meme defaut qui avait ete corrige sur l'installeur de
// Bastion par un manifeste; ici l'appel direct evite d'avoir a generer et
// committer une ressource binaire.
//
// L'appel doit precede la creation de la moindre fenetre: apres, Windows a
// deja decide de l'echelle et refuse d'en changer.
func declarerConscienceResolution() {
	user32 := syscall.NewLazyDLL("user32.dll")
	// Presente depuis Windows 10 1703. Sur plus ancien, l'appel echoue et
	// l'application reste simplement dans son comportement d'avant.
	proc := user32.NewProc("SetProcessDpiAwarenessContext")
	proc.Call(contexteParEcranV2)
}

// --- fenetres de console ---------------------------------------------------

const creerSansFenetre = 0x08000000 // CREATE_NO_WINDOW

// masquerFenetre empeche l'apparition d'une console derriere l'application.
//
// Une application graphique qui lance un programme en ligne de commande voit
// Windows lui ouvrir une console. Elle clignote, se met au premier plan, et
// donne l'impression que quelque chose a mal tourne alors que tout va bien.
func masquerFenetre(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: creerSansFenetre,
	}
}

// --- elevation -------------------------------------------------------------

const (
	masqueGarderProcessus = 0x00000040 // SEE_MASK_NOCLOSEPROCESS
	masqueSansAsync       = 0x00000100 // SEE_MASK_NOASYNC
	fenetreMasquee        = 0          // SW_HIDE
	attenteInfinie        = 0xFFFFFFFF
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

// lancerEleve demande les privileges administrateur pour un seul processus.
//
// L'appel passe par ShellExecuteEx, l'interface que Windows expose justement
// pour cela, plutot que par PowerShell. La version precedente lancait un
// interpreteur qui lancait lui-meme la commande elevee: elle ouvrait une
// fenetre bleue bien visible, ajoutait une dependance a PowerShell, et la
// demande d'autorisation se perdait parfois derriere l'application.
//
// L'application elle-meme reste en utilisateur ordinaire. Faire tourner une
// interface entiere en administrateur donne ces privileges a tout ce qu'elle
// affiche, y compris a une page web; on n'eleve que ce qui en a besoin.
func lancerEleve(binaire string, args []string) error {
	verbe, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	fichier, err := syscall.UTF16PtrFromString(binaire)
	if err != nil {
		return err
	}
	parametres, err := syscall.UTF16PtrFromString(joindreArguments(args))
	if err != nil {
		return err
	}

	info := infoExecution{
		masque:     masqueGarderProcessus | masqueSansAsync,
		verbe:      verbe,
		fichier:    fichier,
		parametres: parametres,
		affichage:  fenetreMasquee,
	}
	info.taille = uint32(unsafe.Sizeof(info))

	shell32 := syscall.NewLazyDLL("shell32.dll")
	ret, _, errno := shell32.NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		// 1223 est ERROR_CANCELLED: l'utilisateur a refuse. Ce n'est pas une
		// panne, c'est une decision, et le message doit le dire.
		if e, ok := errno.(syscall.Errno); ok && e == 1223 {
			return fmt.Errorf("l'autorisation administrateur a été refusée")
		}
		return fmt.Errorf("la demande d'élévation a échoué: %v", errno)
	}
	if info.processus == 0 {
		return fmt.Errorf("le processus élevé n'a pas pu être suivi")
	}
	defer syscall.CloseHandle(info.processus)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("WaitForSingleObject").Call(
		uintptr(info.processus), uintptr(attenteInfinie))
	return nil
}

// joindreArguments assemble une ligne de commande a la facon de Windows.
//
// Les guillemets ne sont pas cosmetiques: un chemin contenant une espace, ce
// qui est le cas de tout profil utilisateur nomme "Terry PASSAVE", serait
// coupe en deux arguments sans eux.
func joindreArguments(args []string) string {
	var parties []string
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		parties = append(parties, a)
	}
	return strings.Join(parties, " ")
}
