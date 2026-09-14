package main

import (
	"context"
	"fmt"
	"runtime"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// OptionsAnalyse porte ce que l'utilisateur peut régler avant de lancer.
type OptionsAnalyse struct {
	Rapide          bool   `json:"rapide"`
	Eleve           bool   `json:"eleve"`
	Profil          string `json:"profil"`
	VerifierPaquets bool   `json:"verifierPaquets"`
}

// Etat décrit ce que la console sait d'elle-même au démarrage.
type Etat struct {
	Version        string `json:"version"`
	Systeme        string `json:"systeme"`
	ArgusTrouve    bool   `json:"argusTrouve"`
	CheminArgus    string `json:"cheminArgus"`
	Probleme       string `json:"probleme,omitempty"`
	NombreAnalyses int    `json:"nombreAnalyses"`
	DossierDonnees string `json:"dossierDonnees"`

	// Les options dont l'effet dépend de la plateforme sont annoncées ici
	// plutôt que devinées par l'interface. Proposer un réglage sans effet est
	// une promesse que l'outil ne tient pas.
	AnalyseRapideUtile  bool `json:"analyseRapideUtile"`
	ElevationDisponible bool `json:"elevationDisponible"`
	VerificationPaquets bool `json:"verificationPaquets"`
}

// Progression est l'état de l'analyse en cours.
type Progression struct {
	EnCours  bool   `json:"enCours"`
	Etape    string `json:"etape"`
	Secondes int    `json:"secondes"`
}

// App expose au frontal les seules opérations dont il a besoin.
type App struct {
	ctx     context.Context
	version string
	binaire string
	analyse *Analyse
}

func NouvelleApp(version string) *App {
	return &App{version: version, analyse: &Analyse{}}
}

func (a *App) demarrage(ctx context.Context) {
	a.ctx = ctx
	if chemin, err := localiserArgus(); err == nil {
		a.binaire = chemin
	}
}

// EtatInitial renseigne l'interface au premier affichage.
func (a *App) EtatInitial() Etat {
	e := Etat{
		Version:             a.version,
		Systeme:             runtime.GOOS,
		AnalyseRapideUtile:  runtime.GOOS != "windows",
		ElevationDisponible: runtime.GOOS == "windows",
		VerificationPaquets: runtime.GOOS == "linux",
	}
	if a.binaire == "" {
		if chemin, err := localiserArgus(); err == nil {
			a.binaire = chemin
		} else {
			e.Probleme = err.Error()
		}
	}
	e.ArgusTrouve = a.binaire != ""
	e.CheminArgus = a.binaire
	if dossier, err := dossierDonnees(); err == nil {
		e.DossierDonnees = dossier
	}
	if analyses, err := analysesConservees(); err == nil {
		e.NombreAnalyses = len(analyses)
	}
	return e
}

// Analyser lance une analyse et renvoie son bulletin.
//
// L'avancement n'est pas renvoyé par cet appel, qui ne rend la main qu'à la
// fin: il est poussé au fil de l'eau par des événements, pour que l'interface
// reste vivante et que l'utilisateur puisse changer d'onglet sans rien perdre.
func (a *App) Analyser(opt OptionsAnalyse) (*Bulletin, error) {
	if a.binaire == "" {
		return nil, fmt.Errorf("le programme argus est introuvable sur cette machine")
	}
	if enCours, _, _ := a.analyse.etat(); enCours {
		return nil, fmt.Errorf("une analyse est déjà en cours")
	}

	a.analyse = &Analyse{encours: true, debut: time.Now(), etape: "démarrage"}
	arret := make(chan struct{})
	go a.diffuserProgression(arret)

	chemin, err := lancerAnalyse(a.binaire, opt, a.analyse)

	close(arret)
	a.analyse.mu.Lock()
	a.analyse.encours = false
	a.analyse.mu.Unlock()
	a.emettreProgression()

	if err != nil {
		return nil, err
	}
	return lireBulletin(chemin)
}

// Annuler abandonne l'analyse en cours.
func (a *App) Annuler() {
	a.analyse.annuler()
}

// EtatAnalyse permet à l'interface de se resynchroniser, par exemple après un
// changement d'onglet, sans attendre le prochain événement.
func (a *App) EtatAnalyse() Progression {
	enCours, etape, s := a.analyse.etat()
	return Progression{EnCours: enCours, Etape: etape, Secondes: s}
}

func (a *App) diffuserProgression(arret <-chan struct{}) {
	t := time.NewTicker(400 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-arret:
			return
		case <-t.C:
			a.emettreProgression()
		}
	}
}

func (a *App) emettreProgression() {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, "progression", a.EtatAnalyse())
}

// DernierBulletin renvoie l'analyse la plus récente, ou rien s'il n'y en a
// aucune. L'absence d'analyse n'est pas une erreur: c'est l'état normal au
// premier lancement, et l'interface doit le présenter comme tel.
func (a *App) DernierBulletin() (*Bulletin, error) {
	analyses, err := analysesConservees()
	if err != nil || len(analyses) == 0 {
		return nil, nil
	}
	return lireBulletin(analyses[0])
}
