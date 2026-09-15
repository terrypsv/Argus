// Copyright (c) 2026 Terry Passave. Tous droits reserves.
// Logiciel proprietaire. Toute utilisation non autorisee est interdite.

//go:build windows

// Package setup contient tout ce que l'installeur fait reellement sur la
// machine: poser les programmes, tenir un manifeste d'integrite, declarer
// l'application a Windows, gerer le PATH systeme, planifier la surveillance, et
// tout retirer proprement.
//
// Trois principes gouvernent ce paquet:
//
//   - Les programmes s'installent dans Program Files, ecrivable par les seuls
//     administrateurs. Un binaire place dans le PATH mais modifiable par un
//     utilisateur ordinaire serait une porte d'entree, pas un outil de securite.
//
//   - La reparation restaure depuis la charge embarquee dans l'installeur,
//     jamais depuis le reseau. Un fichier retelecharge peut avoir ete altere en
//     chemin; la copie embarquee vient de la meme version publiee.
//
//   - Les donnees de l'utilisateur vivent dans son profil et n'appartiennent pas
//     a l'installeur. Ses analyses, sa reference d'integrite et ses constats
//     assumes survivent a une desinstallation, sauf demande explicite.
package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// AppName est le nom affiche et le nom du repertoire d'installation.
	AppName = "Argus"
	// ExeName est la ligne de commande, celle qui doit devenir appelable.
	ExeName = "argus.exe"
	// ConsoleName est l'application de bureau.
	ConsoleName = "argus-console.exe"
	// MaintName est la copie de l'installeur conservee pour reparer et
	// desinstaller hors ligne: elle embarque la meme charge que l'original.
	MaintName = "argus-maintenance.exe"
	// ManifestName porte l'empreinte de chaque fichier pose.
	ManifestName = "integrite.json"
	// TacheName est le nom de la tache planifiee, prefixe par un dossier pour
	// qu'elle se retrouve dans le planificateur au lieu de se perdre parmi des
	// centaines d'autres.
	TacheName = `\Argus\Analyse periodique`

	appID     = `{3D7A4C18-6B92-4E05-A1F3-7C20E9B4D110}`
	uninstKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\` + appID
	envKey    = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

// Charge porte les programmes embarques dans l'installeur.
type Charge struct {
	Argus   []byte
	Console []byte
}

// Composants dit ce que l'utilisateur a choisi d'installer.
type Composants struct {
	Console     bool   `json:"console"`
	AjouterPath bool   `json:"ajouterPath"`
	Raccourci   bool   `json:"raccourci"`
	Frequence   string `json:"frequence"` // "", "quotidienne", "hebdomadaire"
}

// Etat decrit ce qui est present sur la machine au demarrage de l'installeur.
type Etat struct {
	Installe    bool   `json:"installe"`
	Version     string `json:"version"`
	Repertoire  string `json:"repertoire"`
	DansPath    bool   `json:"dansPath"`
	Administrateur bool `json:"administrateur"`
	Protege     bool   `json:"protege"`
	AvecConsole bool   `json:"avecConsole"`
	Surveillance string `json:"surveillance"`
}

// Anomalie signale un fichier absent ou dont l'empreinte ne correspond plus.
type Anomalie struct {
	Nom    string `json:"nom"`
	Raison string `json:"raison"` // "absent" ou "altere"
}

type manifeste struct {
	Version  string            `json:"version"`
	Console  bool              `json:"console"`
	Fichiers map[string]string `json:"fichiers"`
}

// RepertoireParDefaut est la cible proposee, sous Program Files.
func RepertoireParDefaut() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, AppName)
}

// RepertoireReel renvoie le repertoire effectivement utilise: celui enregistre
// lors d'une installation precedente, sinon la cible par defaut. Reparer et
// desinstaller doivent agir la ou le programme est, pas la ou il aurait pu etre.
func RepertoireReel() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstKey, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if d, _, err := k.GetStringValue("InstallLocation"); err == nil && d != "" {
			return d
		}
	}
	return RepertoireParDefaut()
}

// EstProtege dit si le repertoire n'est modifiable que par un administrateur.
//
// Le point compte: un binaire ajoute au PATH mais logeant dans un dossier
// ecrivable par l'utilisateur peut etre remplace par n'importe quel programme
// s'executant en son nom. Tout ce qui tape "argus" executerait alors autre
// chose. On laisse le choix, mais on le dit.
func EstProtege(dir string) bool {
	clean := strings.ToLower(filepath.Clean(dir))
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		base = strings.ToLower(filepath.Clean(base)) + string(filepath.Separator)
		if strings.HasPrefix(clean, base) {
			return true
		}
	}
	return false
}

// EstAdministrateur indique si le processus dispose des droits necessaires.
// Sans eux, rien de ce paquet ne peut aboutir: on prefere le dire clairement
// plutot qu'echouer a mi-chemin en laissant une installation partielle.
func EstAdministrateur() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	membre, err := token.IsMember(sid)
	return err == nil && membre
}

// Detecter lit l'etat courant de la machine.
func Detecter() Etat {
	e := Etat{Repertoire: RepertoireParDefaut(), Administrateur: EstAdministrateur()}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstKey, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue("DisplayVersion"); err == nil {
			e.Installe = true
			e.Version = v
		}
		if d, _, err := k.GetStringValue("InstallLocation"); err == nil && d != "" {
			e.Repertoire = d
		}
	}
	e.DansPath = pathContient(e.Repertoire)
	e.Protege = EstProtege(e.Repertoire)
	e.AvecConsole = fichierExiste(filepath.Join(e.Repertoire, ConsoleName))
	e.Surveillance = FrequenceTache()
	return e
}

// Installer pose les programmes, ecrit le manifeste, declare l'application et
// applique les choix de l'utilisateur. avance est appelee a chaque etape pour
// que l'interface la reflete.
func Installer(dir string, ch Charge, comp Composants, cheminInstalleur, version string,
	avance func(string)) error {

	etape := func(s string) {
		if avance != nil {
			avance(s)
		}
	}
	if !EstAdministrateur() {
		return fmt.Errorf("droits administrateur requis")
	}
	if strings.TrimSpace(dir) == "" {
		dir = RepertoireParDefaut()
	}

	etape("creation du repertoire")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creation du repertoire: %w", err)
	}

	etape("ecriture de la ligne de commande")
	if err := os.WriteFile(filepath.Join(dir, ExeName), ch.Argus, 0o755); err != nil {
		return fmt.Errorf("ecriture de %s: %w", ExeName, err)
	}

	cheminConsole := filepath.Join(dir, ConsoleName)
	if comp.Console {
		etape("ecriture de l'application de bureau")
		if err := os.WriteFile(cheminConsole, ch.Console, 0o755); err != nil {
			return fmt.Errorf("ecriture de %s: %w", ConsoleName, err)
		}
	} else {
		// Une installation allegee apres une complete doit retirer ce qui n'est
		// plus voulu, sinon le choix n'en serait pas un.
		etape("retrait de l'application de bureau")
		_ = os.Remove(cheminConsole)
		_ = supprimerRaccourci()
		_ = SupprimerTache()
	}

	// L'installeur se recopie: reparer et desinstaller doivent rester possibles
	// meme si le fichier telecharge a ete supprime.
	etape("copie de l'outil de maintenance")
	cheminMaint := filepath.Join(dir, MaintName)
	if soi, err := os.ReadFile(cheminInstalleur); err == nil {
		if err := os.WriteFile(cheminMaint, soi, 0o755); err != nil {
			return fmt.Errorf("copie de maintenance: %w", err)
		}
	}

	etape("enregistrement du manifeste d'integrite")
	if err := ecrireManifeste(dir, version, comp.Console); err != nil {
		return fmt.Errorf("manifeste: %w", err)
	}

	etape("declaration a Windows")
	if err := ecrireEntreeDesinstallation(dir, version, cheminMaint, comp.Console); err != nil {
		return fmt.Errorf("entree de desinstallation: %w", err)
	}

	if comp.AjouterPath {
		etape("ajout au PATH systeme")
		if err := AjouterAuPath(dir); err != nil {
			return fmt.Errorf("PATH: %w", err)
		}
		etape("diffusion de l'environnement")
		DiffuserEnvironnement()
	}

	if comp.Console && comp.Raccourci {
		etape("creation du raccourci")
		if err := creerRaccourci(cheminConsole); err != nil {
			// Un raccourci manquant n'empeche pas d'utiliser le programme: on le
			// signale sans faire echouer l'installation.
			etape("raccourci non cree: " + err.Error())
		}
	}

	if comp.Console && comp.Frequence != "" {
		etape("planification de la surveillance")
		if err := PlanifierTache(cheminConsole, comp.Frequence); err != nil {
			return fmt.Errorf("tache planifiee: %w", err)
		}
	} else {
		_ = SupprimerTache()
	}
	return nil
}

// Verifier compare chaque fichier du manifeste a son empreinte enregistree.
// Un manifeste absent est signale comme tel: on ne peut rien affirmer sans lui.
func Verifier() ([]Anomalie, error) {
	dir := RepertoireReel()
	m, err := lireManifeste(dir)
	if err != nil {
		return nil, fmt.Errorf("manifeste illisible: %w", err)
	}

	var anomalies []Anomalie
	for nom, attendu := range m.Fichiers {
		obtenu, err := empreinte(filepath.Join(dir, nom))
		if err != nil {
			anomalies = append(anomalies, Anomalie{Nom: nom, Raison: "absent"})
			continue
		}
		if obtenu != attendu {
			anomalies = append(anomalies, Anomalie{Nom: nom, Raison: "altere"})
		}
	}
	return anomalies, nil
}

// Reparer restaure les fichiers manquants ou alteres depuis la charge embarquee,
// puis reecrit le manifeste et retablit l'entree PATH si elle a disparu.
func Reparer(ch Charge, cheminInstalleur, version string, avance func(string)) error {
	etape := func(s string) {
		if avance != nil {
			avance(s)
		}
	}
	if !EstAdministrateur() {
		return fmt.Errorf("droits administrateur requis")
	}
	dir := RepertoireReel()

	etape("verification des empreintes")
	anomalies, err := Verifier()
	if err != nil {
		// Manifeste perdu: on repose tout, c'est le cas le plus sur.
		etape("manifeste absent, restauration complete")
		comp := Composants{
			Console:     fichierExiste(filepath.Join(dir, ConsoleName)),
			AjouterPath: pathContient(dir),
			Frequence:   FrequenceTache(),
		}
		return Installer(dir, ch, comp, cheminInstalleur, version, avance)
	}
	if len(anomalies) == 0 {
		etape("aucun fichier manquant ni altere")
	}

	m, _ := lireManifeste(dir)
	for _, a := range anomalies {
		etape("restauration de " + a.Nom)
		switch a.Nom {
		case ExeName:
			if err := os.WriteFile(filepath.Join(dir, ExeName), ch.Argus, 0o755); err != nil {
				return err
			}
		case ConsoleName:
			if err := os.WriteFile(filepath.Join(dir, ConsoleName), ch.Console, 0o755); err != nil {
				return err
			}
		case MaintName:
			if soi, err := os.ReadFile(cheminInstalleur); err == nil {
				if err := os.WriteFile(filepath.Join(dir, MaintName), soi, 0o755); err != nil {
					return err
				}
			}
		}
	}

	etape("mise a jour du manifeste")
	if err := ecrireManifeste(dir, version, m.Console); err != nil {
		return err
	}

	if !pathContient(dir) {
		etape("retablissement du PATH systeme")
		if err := AjouterAuPath(dir); err != nil {
			return err
		}
		DiffuserEnvironnement()
	}
	return nil
}

// Desinstaller retire le logiciel: tache planifiee, raccourci, PATH, registre et
// fichiers. Chaque etape est tentee meme si la precedente echoue, et les echecs
// sont remontes: une desinstallation qui laisse des traces en silence est pire
// qu'une desinstallation qui dit ce qu'elle n'a pas pu faire.
//
// Les donnees de l'utilisateur ne sont touchees que si effacerDonnees est vrai.
// Ses analyses forment un historique, sa reference d'integrite fige un jugement
// porte un jour precis et ses constats assumes sont des decisions motivees:
// aucun de ces trois n'est remplacable, et les effacer par defaut serait
// detruire ce que l'outil sert a construire.
func Desinstaller(effacerDonnees bool, avance func(string)) error {
	etape := func(s string) {
		if avance != nil {
			avance(s)
		}
	}
	if !EstAdministrateur() {
		return fmt.Errorf("droits administrateur requis")
	}
	dir := RepertoireReel()
	var problemes []string

	etape("suppression de la tache planifiee")
	if err := SupprimerTache(); err != nil {
		problemes = append(problemes, "tache: "+err.Error())
	}

	etape("suppression du raccourci")
	_ = supprimerRaccourci()

	etape("retrait du PATH systeme")
	if err := RetirerDuPath(dir); err != nil {
		problemes = append(problemes, "PATH: "+err.Error())
	}
	DiffuserEnvironnement()

	etape("suppression de l'entree de desinstallation")
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstKey); err != nil {
		problemes = append(problemes, "registre: "+err.Error())
	}

	etape("suppression des fichiers")
	if err := supprimerArborescence(dir); err != nil {
		problemes = append(problemes, "fichiers: "+err.Error())
	}

	if effacerDonnees {
		etape("suppression des donnees de l'utilisateur")
		if base, err := os.UserConfigDir(); err == nil {
			if err := os.RemoveAll(filepath.Join(base, AppName)); err != nil {
				problemes = append(problemes, "donnees: "+err.Error())
			}
		}
	}

	etape("verification du retrait")
	if Detecter().Installe {
		problemes = append(problemes, "l'entree de registre est toujours presente")
	}

	if len(problemes) > 0 {
		return fmt.Errorf("desinstallation incomplete - %s", strings.Join(problemes, " | "))
	}
	return nil
}

// ---------- tache planifiee ----------

// PlanifierTache cree l'analyse periodique.
//
// La tache lance l'application de bureau plutot que la ligne de commande, et ce
// n'est pas un detail. Un programme de console lance par le planificateur ouvre
// une fenetre noire a chaque execution; l'application, elle, est un programme
// graphique qui, dans ce mode, analyse puis se termine sans rien afficher.
//
// Elle tourne sous le compte de l'utilisateur et non sous le compte systeme:
// celui-ci ne voit ni les profils de navigateur, ni le repertoire personnel, et
// la moitie des controles reviendraient vides. Le niveau le plus eleve
// disponible est demande, ce qui evite une demande d'autorisation a chaque
// execution.
func PlanifierTache(cheminConsole, frequence string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("compte utilisateur indeterminable: %w", err)
	}

	args := []string{
		"/Create", "/F",
		"/TN", TacheName,
		"/TR", `"` + cheminConsole + `" --tache`,
		"/RU", u.Username,
		"/RL", "HIGHEST",
		"/IT", // seulement quand la session est ouverte: evite un mot de passe
		"/ST", "09:00",
	}
	switch frequence {
	case "quotidienne":
		args = append(args, "/SC", "DAILY")
	case "hebdomadaire":
		args = append(args, "/SC", "WEEKLY", "/D", "MON")
	default:
		return fmt.Errorf("frequence inconnue: %s", frequence)
	}

	sortie, err := executer("schtasks.exe", args...)
	if err != nil {
		return fmt.Errorf("%s", sortie)
	}
	return nil
}

// SupprimerTache retire l'analyse periodique. L'absence de tache n'est pas une
// erreur: desinstaller une machine qui n'en avait pas doit reussir.
func SupprimerTache() error {
	if FrequenceTache() == "" {
		return nil
	}
	if sortie, err := executer("schtasks.exe", "/Delete", "/TN", TacheName, "/F"); err != nil {
		return fmt.Errorf("%s", sortie)
	}
	return nil
}

// FrequenceTache lit la periodicite configuree, ou une chaine vide.
func FrequenceTache() string {
	sortie, err := executer("schtasks.exe", "/Query", "/TN", TacheName, "/FO", "LIST")
	if err != nil {
		return ""
	}
	bas := strings.ToLower(sortie)
	switch {
	case strings.Contains(bas, "daily") || strings.Contains(bas, "quotidien"):
		return "quotidienne"
	case strings.Contains(bas, "weekly") || strings.Contains(bas, "hebdomadaire"):
		return "hebdomadaire"
	}
	// La tache existe mais sa periodicite n'a pas ete reconnue: on ne devine
	// pas, on le dit.
	return "inconnue"
}

// ---------- raccourci ----------

// creerRaccourci pose une entree dans le menu Demarrer, pour tous les
// utilisateurs puisque le programme est installe pour la machine.
//
// Le raccourci est fabrique par PowerShell faute d'interface Go pour l'objet
// COM qui le produit. C'est laid et c'est la facon documentee de le faire.
func creerRaccourci(cible string) error {
	dossier := filepath.Join(os.Getenv("ProgramData"),
		`Microsoft\Windows\Start Menu\Programs`, AppName)
	if err := os.MkdirAll(dossier, 0o755); err != nil {
		return err
	}
	lien := filepath.Join(dossier, "Console Argus.lnk")

	script := fmt.Sprintf(
		`$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s');`+
			`$s.TargetPath='%s';$s.WorkingDirectory='%s';`+
			`$s.Description='Console Argus';$s.Save()`,
		echapperPS(lien), echapperPS(cible), echapperPS(filepath.Dir(cible)))

	if sortie, err := executer("powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		return fmt.Errorf("%s", sortie)
	}
	return nil
}

func supprimerRaccourci() error {
	dossier := filepath.Join(os.Getenv("ProgramData"),
		`Microsoft\Windows\Start Menu\Programs`, AppName)
	return os.RemoveAll(dossier)
}

func echapperPS(s string) string { return strings.ReplaceAll(s, "'", "''") }

// executer lance un programme sans ouvrir de fenetre et renvoie sa sortie.
func executer(nom string, args ...string) (string, error) {
	cmd := exec.Command(nom, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	sortie, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(sortie)), err
}

func fichierExiste(chemin string) bool {
	fi, err := os.Stat(chemin)
	return err == nil && !fi.IsDir()
}

// ---------- manifeste ----------

func ecrireManifeste(dir, version string, avecConsole bool) error {
	m := manifeste{Version: version, Console: avecConsole, Fichiers: map[string]string{}}
	noms := []string{ExeName, MaintName}
	if avecConsole {
		noms = append(noms, ConsoleName)
	}
	for _, nom := range noms {
		if h, err := empreinte(filepath.Join(dir, nom)); err == nil {
			m.Fichiers[nom] = h
		}
	}
	donnees, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestName), donnees, 0o644)
}

func lireManifeste(dir string) (manifeste, error) {
	var m manifeste
	donnees, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(donnees, &m)
	return m, err
}

func empreinte(chemin string) (string, error) {
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return "", err
	}
	somme := sha256.Sum256(donnees)
	return hex.EncodeToString(somme[:]), nil
}

// ---------- registre ----------

func ecrireEntreeDesinstallation(dir, version, cheminMaint string, avecConsole bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	// L'icone affichee par Windows est celle de l'application quand elle est
	// installee, sinon celle de la ligne de commande: une entree sans icone se
	// remarque dans la liste des programmes, et pas en bien.
	icone := filepath.Join(dir, ExeName)
	if avecConsole {
		icone = filepath.Join(dir, ConsoleName)
	}

	valeurs := map[string]string{
		"DisplayName":     AppName,
		"DisplayVersion":  version,
		"Publisher":       "Steelveil",
		"InstallLocation": dir,
		"DisplayIcon":     icone,
		"UninstallString": `"` + cheminMaint + `" --desinstaller`,
		"ModifyPath":      `"` + cheminMaint + `"`,
		"URLInfoAbout":    "https://github.com/terrypsv/Argus",
	}
	for nom, v := range valeurs {
		if err := k.SetStringValue(nom, v); err != nil {
			return err
		}
	}
	return k.SetDWordValue("NoModify", 0)
}

// ---------- PATH systeme ----------

func lirePath() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Path")
	return v, err
}

func ecrirePath(v string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	// EXPAND_SZ: le PATH systeme contient des variables comme %SystemRoot%,
	// l'ecrire en chaine simple les figerait definitivement.
	return k.SetExpandStringValue("Path", v)
}

func pathContient(dir string) bool {
	v, err := lirePath()
	if err != nil {
		return false
	}
	for _, part := range strings.Split(v, ";") {
		if strings.EqualFold(strings.TrimSpace(part), dir) {
			return true
		}
	}
	return false
}

// AjouterAuPath ajoute dir au PATH systeme sans dupliquer ni ecraser l'existant.
func AjouterAuPath(dir string) error {
	if pathContient(dir) {
		return nil
	}
	v, err := lirePath()
	if err != nil {
		return err
	}
	v = strings.TrimRight(v, ";")
	if v != "" {
		v += ";"
	}
	return ecrirePath(v + dir)
}

// RetirerDuPath retire dir du PATH sans laisser d'entree vide ni de residu.
func RetirerDuPath(dir string) error {
	v, err := lirePath()
	if err != nil {
		return err
	}
	var gardes []string
	for _, part := range strings.Split(v, ";") {
		p := strings.TrimSpace(part)
		if p == "" || strings.EqualFold(p, dir) {
			continue
		}
		gardes = append(gardes, p)
	}
	return ecrirePath(strings.Join(gardes, ";"))
}

// DiffuserEnvironnement previent Windows que l'environnement a change, pour que
// les nouveaux processus voient le PATH sans qu'il faille se reconnecter.
func DiffuserEnvironnement() {
	const (
		toutesFenetres  = 0xFFFF
		messageReglage  = 0x001A
		abandonSiFige   = 0x0002
	)
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	param, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var resultat uintptr
	_, _, _ = proc.Call(
		uintptr(toutesFenetres), uintptr(messageReglage), 0,
		uintptr(unsafe.Pointer(param)), uintptr(abandonSiFige),
		uintptr(5000), uintptr(unsafe.Pointer(&resultat)),
	)
}

// ---------- suppression ----------

// supprimerArborescence supprime le repertoire d'installation.
//
// Un fichier peut etre verrouille parce qu'il s'execute: le binaire de
// maintenance tourne depuis le repertoire qu'il doit effacer. Dans ce cas il est
// programme pour suppression au prochain demarrage plutot que de faire echouer
// l'operation entiere.
func supprimerArborescence(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}

	var verrouilles []string
	entrees, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entrees {
		p := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			verrouilles = append(verrouilles, e.Name())
			marquerPourSuppression(p)
		}
	}
	if err := os.Remove(dir); err != nil {
		marquerPourSuppression(dir)
		if len(verrouilles) > 0 {
			return fmt.Errorf("verrouille, suppression au prochain demarrage: %s",
				strings.Join(verrouilles, ", "))
		}
		return fmt.Errorf("repertoire supprime au prochain demarrage")
	}
	return nil
}

func marquerPourSuppression(chemin string) {
	const retarderJusquAuRedemarrage = 0x4
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("MoveFileExW")
	depuis, err := windows.UTF16PtrFromString(chemin)
	if err != nil {
		return
	}
	_, _, _ = proc.Call(uintptr(unsafe.Pointer(depuis)), 0,
		uintptr(retarderJusquAuRedemarrage))
}
