package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	DateVersion    string `json:"dateVersion"`
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
		DateVersion:         dateCompilation,
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

// Accepter assume un constat après examen.
//
// Les trois garde-fous de la ligne de commande sont conservés parce qu'ils font
// tout l'intérêt du dispositif. Le motif est obligatoire: une exception que
// personne ne peut expliquer six mois plus tard est pire que le constat
// qu'elle recouvre. Le constat reste visible dans chaque rapport, avec sa
// gravité d'origine. Et l'échéance force une revue, sans quoi "temporaire"
// devient "permanent" en silence.
func (a *App) Accepter(id, motif, par string, jours int) error {
	if a.binaire == "" {
		return fmt.Errorf("le programme argus est introuvable sur cette machine")
	}
	if strings.TrimSpace(motif) == "" {
		return fmt.Errorf("un motif est obligatoire")
	}

	args := []string{"accept", id, "--reason", motif}
	if strings.TrimSpace(par) != "" {
		args = append(args, "--by", par)
	}
	if jours > 0 {
		args = append(args, "--days", strconv.Itoa(jours))
	}
	if c, err := cheminExceptions(); err == nil {
		args = append(args, "--exceptions", c)
	}

	_, err := executerCommande(a.binaire, args...)
	return err
}

// Revoquer annule une acceptation. Le constat redevient un écart ouvert, et la
// note baissera d'autant à la prochaine analyse.
func (a *App) Revoquer(id string) error {
	if a.binaire == "" {
		return fmt.Errorf("le programme argus est introuvable sur cette machine")
	}
	args := []string{"unaccept", id}
	if c, err := cheminExceptions(); err == nil {
		args = append(args, "--exceptions", c)
	}
	_, err := executerCommande(a.binaire, args...)
	return err
}

// PrendreReference enregistre les empreintes des fichiers critiques.
//
// C'est le geste le plus lourd de conséquences de tout l'outil, et il n'a rien
// d'un bouton anodin: la référence fige un état supposé sain, et tout ce qui
// s'en écarte ensuite sera signalé. La prendre sur une machine déjà altérée
// enregistre l'altération comme légitime, et le contrôle d'intégrité ne verra
// plus jamais rien.
//
// L'interface doit donc le dire avant, pas après.
func (a *App) PrendreReference(eleve bool) error {
	if a.binaire == "" {
		return fmt.Errorf("le programme argus est introuvable sur cette machine")
	}
	reference, err := cheminReference()
	if err != nil {
		return err
	}
	if eleve && runtime.GOOS == "windows" {
		return prendreReferenceElevee(a.binaire, reference)
	}
	_, err = executerCommande(a.binaire, "baseline", "--baseline", reference)
	return err
}

// ResumeAnalyse est une analyse réduite à ce qu'une liste doit montrer.
//
// Les rapports complets pèsent plusieurs centaines de kilooctets chacun: les
// renvoyer tous pour dessiner un tableau reviendrait à charger l'historique
// entier en mémoire pour en afficher deux colonnes.
type ResumeAnalyse struct {
	Chemin       string    `json:"chemin"`
	Date         time.Time `json:"date"`
	Machine      string    `json:"machine"`
	Durcissement int       `json:"durcissement"`
	MentionD     string    `json:"mentionD"`
	Integrite    int       `json:"integrite"`
	MentionI     string    `json:"mentionI"`
	Ecarts       int       `json:"ecarts"`
	Acceptes     int       `json:"acceptes"`
	Profil       string    `json:"profil"`
}

// Historique liste les analyses conservées, de la plus récente à la plus
// ancienne.
//
// C'est ce que la ligne de commande ne peut pas faire: elle produit des
// rapports, elle ne les accumule pas. Une note isolée dit l'état d'un jour;
// une suite de notes dit si la machine se dégrade, et à partir de quand.
func (a *App) Historique() ([]ResumeAnalyse, error) {
	chemins, err := analysesConservees()
	if err != nil {
		return nil, err
	}

	var out []ResumeAnalyse
	for _, c := range chemins {
		b, err := lireBulletin(c)
		if err != nil {
			// Un rapport illisible ne doit pas faire disparaître les autres:
			// il est simplement ignoré, et l'historique reste consultable.
			continue
		}
		ouverts := 0
		for _, f := range b.Constats {
			if f.Ouvert() {
				ouverts++
			}
		}
		out = append(out, ResumeAnalyse{
			Chemin:       c,
			Date:         b.Fin,
			Machine:      b.Machine.Nom,
			Durcissement: b.Durcissement.Note,
			MentionD:     b.Durcissement.Mention,
			Integrite:    b.Integrite.Note,
			MentionI:     b.Integrite.Mention,
			Ecarts:       ouverts,
			Acceptes:     b.Comptes["accepted"],
			Profil:       b.Profil,
		})
	}
	return out, nil
}

// ChargerAnalyse ouvre une analyse conservée.
//
// Le chemin vient de la liste renvoyée par Historique, jamais d'une saisie:
// la console ne lit que ce qu'elle a elle-même écrit.
func (a *App) ChargerAnalyse(chemin string) (*Bulletin, error) {
	chemins, err := analysesConservees()
	if err != nil {
		return nil, err
	}
	for _, c := range chemins {
		if c == chemin {
			return lireBulletin(c)
		}
	}
	return nil, fmt.Errorf("cette analyse ne fait pas partie de l'historique")
}

// LesReglages renvoie les préférences conservées.
func (a *App) LesReglages() Reglages { return lireReglages() }

// EnregistrerReglages conserve les préférences.
func (a *App) EnregistrerReglages(r Reglages) error { return ecrireReglages(r) }

// OuvrirDossierDonnees montre où la console range ce qu'elle produit.
//
// Le chemin est affiché ailleurs dans l'interface, mais un chemin affiché se
// recopie à la main; un dossier qui s'ouvre se parcourt.
func (a *App) OuvrirDossierDonnees() error {
	base, err := dossierDonnees()
	if err != nil {
		return err
	}
	return ouvrirCible(base)
}

// EffacerHistorique supprime les analyses conservées.
//
// La référence d'intégrité et les constats assumés ne sont pas touchés, et ce
// n'est pas un oubli: l'historique est une commodité, tandis que la référence
// fige un jugement porté un jour précis et que les exceptions sont des
// décisions motivées. Les effacer ensemble mettrait sur le même plan des
// choses qui n'ont pas la même valeur.
func (a *App) EffacerHistorique() (int, error) {
	chemins, err := analysesConservees()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range chemins {
		if os.Remove(c) == nil {
			n++
		}
	}
	return n, nil
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
