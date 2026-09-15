package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Ce fichier répond à une question simple posée par quelqu'un qui ne connaît
// pas la ligne de commande: "d'accord, mais où je vais pour corriger ça ?"
//
// Argus lit, il ne modifie pas, et ce n'est pas une limite technique mais une
// décision. Un outil d'audit qui reconfigure la machine peut la casser -
// fermer le port 445 coupe le partage de fichiers, activer le chiffrement sans
// conserver la clé de récupération enferme quelqu'un hors de son disque - et
// il devient surtout un moyen de reconfigurer le système: qui le pilote pilote
// la machine.
//
// Ce que la console peut faire sans franchir cette ligne, c'est emmener au bon
// endroit. La décision reste entière, mais on ne cherche plus.

// Destination est l'endroit où se règle un constat.
type Destination struct {
	Libelle string `json:"libelle"`
	Cible   string `json:"cible"`
}

// destinations associe un constat à l'écran qui le gouverne.
//
// Les adresses ms-settings sont celles des Réglages de Windows, les fichiers
// .msc des consoles d'administration. Aucune n'est inventée: une entrée fausse
// ouvrirait une fenêtre sans rapport, ce qui est pire que pas de bouton du tout.
var destinations = map[string]Destination{
	"BL-OFF":      {"Ouvrir le chiffrement du disque", "ms-settings:deviceencryption"},
	"BL-UNKNOWN":  {"Ouvrir le chiffrement du disque", "ms-settings:deviceencryption"},
	"FW-OFF":      {"Ouvrir la sécurité Windows", "windowsdefender:"},
	"AV-RTP":      {"Ouvrir la sécurité Windows", "windowsdefender:"},
	"AV-SIG":      {"Ouvrir la sécurité Windows", "windowsdefender:"},
	"UAC-OFF":     {"Ouvrir le contrôle de compte", "UserAccountControlSettings.exe"},
	"SMB1-ON":     {"Ouvrir les fonctionnalités Windows", "OptionalFeatures.exe"},
	"RDP-ON":      {"Ouvrir le bureau à distance", "ms-settings:remotedesktop"},
	"RDP-NONLA":   {"Ouvrir le bureau à distance", "ms-settings:remotedesktop"},
	"RUN-SUSP":    {"Ouvrir les applications de démarrage", "ms-settings:startupapps"},
	"RUN-INV":     {"Ouvrir les applications de démarrage", "ms-settings:startupapps"},
	"TASK-SUSP":   {"Ouvrir le planificateur de tâches", "taskschd.msc"},
	"ADM-LIST":    {"Ouvrir les comptes d'utilisateurs", "netplwiz.exe"},
	"CERT-INTERCEPT": {"Ouvrir les certificats de la machine", "certlm.msc"},
	"CERT-LOCAL":  {"Ouvrir les certificats de la machine", "certlm.msc"},
	"CERT-ROOT-INV": {"Ouvrir les certificats de la machine", "certlm.msc"},
	"NET-PORT-TCP-445": {"Ouvrir le pare-feu", "WF.msc"},
	"NET-PORT-TCP-3389": {"Ouvrir le pare-feu", "WF.msc"},
	"NET-LISTEN":  {"Ouvrir le pare-feu", "WF.msc"},
	"DISK-LOW-C":  {"Ouvrir le stockage", "ms-settings:storagesense"},
	"DISK-FULL-C": {"Ouvrir le stockage", "ms-settings:storagesense"},
}

// destinationDe renvoie l'écran associé à un constat, s'il y en a un.
//
// Les identifiants de port portent leur numéro, ce qui en fait une famille
// plutôt qu'une liste finie: on retombe sur le pare-feu pour tous.
func destinationDe(id string) (Destination, bool) {
	if d, ok := destinations[id]; ok {
		return d, true
	}
	if strings.HasPrefix(id, "NET-PORT-") {
		return Destination{"Ouvrir le pare-feu", "WF.msc"}, true
	}
	if strings.HasPrefix(id, "DISK-LOW-") || strings.HasPrefix(id, "DISK-FULL-") {
		return Destination{"Ouvrir le stockage", "ms-settings:storagesense"}, true
	}
	return Destination{}, false
}

// motifChemin reconnaît un chemin Windows absolu dans une ligne de preuve.
//
// Les preuves ne sont pas normalisées: une entrée de registre mêle un nom, un
// type et un chemin entre guillemets sur la même ligne. On extrait le chemin
// plutôt que d'exiger que la preuve en soit un.
var motifChemin = regexp.MustCompile(`[A-Za-z]:\\[^"'\r\n]+`)

// CheminDeLaPreuve renvoie le fichier désigné par une preuve, s'il existe.
//
// L'existence est vérifiée avant de proposer le bouton: emmener quelqu'un vers
// un fichier absent le laisserait devant un message d'erreur de l'Explorateur,
// et lui ferait douter du reste du rapport.
func (a *App) CheminDeLaPreuve(ligne string) string {
	brut := motifChemin.FindString(ligne)
	if brut == "" {
		return ""
	}
	chemin := strings.TrimRight(strings.TrimSpace(brut), `"' `)
	if _, err := os.Stat(chemin); err != nil {
		return ""
	}
	return chemin
}

// DestinationDuConstat expose au frontal l'écran associé à un constat.
func (a *App) DestinationDuConstat(id string) *Destination {
	if d, ok := destinationDe(id); ok {
		return &d
	}
	return nil
}

// OuvrirReglage ouvre l'écran de Windows qui gouverne un constat.
func (a *App) OuvrirReglage(id string) error {
	d, ok := destinationDe(id)
	if !ok {
		return fmt.Errorf("aucun écran connu pour ce constat")
	}
	return ouvrirCible(d.Cible)
}

// OuvrirEmplacement ouvre l'Explorateur sur un fichier, sélectionné.
func (a *App) OuvrirEmplacement(chemin string) error {
	if chemin == "" {
		return fmt.Errorf("aucun emplacement à ouvrir")
	}
	if _, err := os.Stat(chemin); err != nil {
		return fmt.Errorf("ce fichier n'existe plus: %s", chemin)
	}
	return selectionnerDansExplorateur(chemin)
}

// --- navigateurs -----------------------------------------------------------

// Les extensions n'ont pas d'écran Windows: elles se gèrent dans le navigateur
// qui les héberge. La page existe, mais son adresse n'est pas une adresse web
// et le shell ne sait pas l'ouvrir: il faut lancer le navigateur en lui
// passant l'adresse.

type navigateur struct {
	nom      string
	page     string
	chemins  []string
}

var navigateurs = []navigateur{
	{"Chrome", "chrome://extensions", []string{
		`%ProgramFiles%\Google\Chrome\Application\chrome.exe`,
		`%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe`,
		`%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`,
	}},
	{"Edge", "edge://extensions", []string{
		`%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe`,
		`%ProgramFiles%\Microsoft\Edge\Application\msedge.exe`,
	}},
	{"Brave", "brave://extensions", []string{
		`%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe`,
		`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe`,
	}},
	{"Vivaldi", "vivaldi://extensions", []string{
		`%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe`,
		`%ProgramFiles%\Vivaldi\Application\vivaldi.exe`,
	}},
	{"Opera", "opera://extensions", []string{
		`%LOCALAPPDATA%\Programs\Opera\launcher.exe`,
	}},
	{"Firefox", "about:addons", []string{
		`%ProgramFiles%\Mozilla Firefox\firefox.exe`,
		`%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe`,
	}},
}

// motifVariable reconnaît une variable d'environnement à la façon de Windows.
//
// os.ExpandEnv ne convient pas ici: il attend la forme $NOM et s'arrête au
// premier caractère non alphanumérique, ce qui coupe ProgramFiles(x86) en
// plein milieu et produit un chemin qui n'existe nulle part.
var motifVariable = regexp.MustCompile(`%([^%]+)%`)

func developper(chemin string) string {
	return motifVariable.ReplaceAllStringFunc(chemin, func(m string) string {
		return os.Getenv(strings.Trim(m, "%"))
	})
}

// trouverNavigateur localise le programme d'un navigateur installé.
func trouverNavigateur(nom string) (navigateur, string, bool) {
	for _, n := range navigateurs {
		if !strings.EqualFold(n.nom, nom) {
			continue
		}
		for _, c := range n.chemins {
			chemin := developper(c)
			if chemin != "" && !strings.Contains(chemin, "%") && fichierExiste(chemin) {
				return n, chemin, true
			}
		}
		return n, "", false
	}
	return navigateur{}, "", false
}

// NavigateurDeLaPreuve reconnaît le navigateur nommé par une preuve.
//
// Les preuves du contrôle d'extensions commencent par le navigateur et son
// profil, sous la forme "Chrome / Profile 1: ...". On n'ouvre le bouton que si
// ce navigateur est effectivement installé ici: proposer d'ouvrir un programme
// absent est une impasse.
func (a *App) NavigateurDeLaPreuve(ligne string) string {
	avant := ligne
	if i := strings.Index(ligne, ":"); i > 0 {
		avant = ligne[:i]
	}
	if i := strings.Index(avant, "/"); i > 0 {
		avant = avant[:i]
	}
	nom := strings.TrimSpace(avant)
	if _, _, ok := trouverNavigateur(nom); ok {
		return nom
	}
	return ""
}

// OuvrirExtensions ouvre la page des extensions d'un navigateur.
func (a *App) OuvrirExtensions(nom string) error {
	n, chemin, ok := trouverNavigateur(nom)
	if !ok {
		return fmt.Errorf("%s ne semble pas installé sur cette machine", nom)
	}
	return lancerProgramme(chemin, n.page)
}
