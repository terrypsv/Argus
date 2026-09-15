package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/terrypsv/Argus/installer/windows-app/internal/setup"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App expose au frontal les seules opérations dont il a besoin.
//
// Toute la logique vit dans le paquet setup, et ce n'est pas une préférence de
// rangement: ce qui touche au registre, au PATH et au planificateur doit
// pouvoir se relire d'une traite, sans être entrecoupé d'appels à l'interface.
type App struct {
	ctx     context.Context
	version string
	depart  string
}

func NouvelleApp(version string) *App { return &App{version: version} }

func (a *App) demarrage(ctx context.Context) { a.ctx = ctx }

// Depart indique l'écran sur lequel s'ouvrir, selon la façon dont l'installeur
// a été lancé.
func (a *App) Depart() string { return a.depart }

// Version est celle de la charge embarquée, pas celle qui est installée.
func (a *App) Version() string { return a.version }

// EtatMachine lit ce qui est présent avant toute décision.
func (a *App) EtatMachine() setup.Etat { return setup.Detecter() }

// RepertoireParDefaut est la cible proposée.
func (a *App) RepertoireParDefaut() string { return setup.RepertoireParDefaut() }

// EstProtege dit si un répertoire n'est modifiable que par un administrateur.
//
// L'interface s'en sert pour avertir quand l'utilisateur choisit un
// emplacement quelconque: un programme appelable depuis n'importe où mais
// remplaçable par n'importe quel processus de l'utilisateur est une porte
// d'entrée, et il vaut mieux le dire que l'interdire.
func (a *App) EstProtege(dir string) bool { return setup.EstProtege(dir) }

// DossierDonnees est l'endroit où la console range analyses, référence et
// exceptions. L'écran de désinstallation l'affiche, pour que personne ne coche
// la case d'effacement sans savoir ce qu'elle emporte.
func (a *App) DossierDonnees() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, setup.AppName)
}

func (a *App) avance(s string) {
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, "avance", s)
	}
}

// Installer applique les choix de l'utilisateur.
func (a *App) Installer(dir string, comp setup.Composants) error {
	soi, err := os.Executable()
	if err != nil {
		return fmt.Errorf("chemin de l'installeur introuvable: %w", err)
	}
	charge := setup.Charge{Argus: chargeArgus, Console: chargeConsole}
	return setup.Installer(dir, charge, comp, soi, a.version, a.avance)
}

// Verifier compare les fichiers installés à leurs empreintes.
func (a *App) Verifier() ([]setup.Anomalie, error) { return setup.Verifier() }

// Reparer restaure ce qui manque ou a changé, depuis la charge embarquée.
func (a *App) Reparer() error {
	soi, err := os.Executable()
	if err != nil {
		return err
	}
	charge := setup.Charge{Argus: chargeArgus, Console: chargeConsole}
	return setup.Reparer(charge, soi, a.version, a.avance)
}

// Desinstaller retire le logiciel, et les données seulement si on le demande.
func (a *App) Desinstaller(effacerDonnees bool) error {
	return setup.Desinstaller(effacerDonnees, a.avance)
}

// OuvrirConsole lance l'application fraîchement installée.
func (a *App) OuvrirConsole() error {
	chemin := filepath.Join(setup.RepertoireReel(), setup.ConsoleName)
	cmd := exec.Command(chemin)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

// Quitter ferme l'installeur.
func (a *App) Quitter() {
	if a.ctx != nil {
		wruntime.Quit(a.ctx)
	}
}
