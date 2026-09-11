package main

import (
	"context"
	"fmt"
	"runtime"
)

// OptionsAnalyse porte ce que l'utilisateur peut régler avant de lancer.
type OptionsAnalyse struct {
	Rapide          bool   `json:"rapide"`
	Eleve           bool   `json:"eleve"`
	Profil          string `json:"profil"`
	VerifierPaquets bool   `json:"verifierPaquets"`
}

// Etat décrit ce que la console sait d'elle-même au démarrage.
//
// Tout est renvoyé en un seul appel plutôt qu'en plusieurs: l'interface a
// besoin de l'ensemble pour dessiner son premier écran, et trois allers-retours
// produiraient trois états d'affichage intermédiaires.
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
	// une promesse que l'outil ne tient pas, et l'utilisateur le constate sans
	// jamais comprendre pourquoi.
	AnalyseRapideUtile   bool `json:"analyseRapideUtile"`
	ElevationDisponible  bool `json:"elevationDisponible"`
	VerificationPaquets  bool `json:"verificationPaquets"`
}

// App expose au frontal les seules opérations dont il a besoin.
type App struct {
	ctx     context.Context
	version string
	binaire string
}

func NouvelleApp(version string) *App {
	return &App{version: version}
}

func (a *App) demarrage(ctx context.Context) {
	a.ctx = ctx
	// L'absence d'Argus n'empêche pas la console de s'ouvrir: elle doit pouvoir
	// le dire clairement plutôt que de refuser de démarrer sur une erreur que
	// personne ne lit.
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
func (a *App) Analyser(opt OptionsAnalyse) (*Bulletin, error) {
	if a.binaire == "" {
		return nil, fmt.Errorf("le programme argus est introuvable sur cette machine")
	}
	chemin, err := lancerAnalyse(a.binaire, opt)
	if err != nil {
		return nil, err
	}
	return lireBulletin(chemin)
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
