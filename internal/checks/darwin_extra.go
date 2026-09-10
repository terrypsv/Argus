//go:build darwin

package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// These checks close the gap between macOS and the other two platforms, which
// covered accounts and remote access while macOS did not.
//
// Every parser here refuses to guess. macOS renames and rewrites its command
// line tools between releases, and this project has already been caught out by
// kextstat, plutil and codesign. When output does not match what the check
// expects, it reports an error finding rather than an all-clear: an unchecked
// area must never be presentable as a clean result.

// macAccounts inspects local accounts through the directory service. /etc/passwd
// exists on macOS but is vestigial; real accounts live in OpenDirectory, so
// reading the file would report almost nothing and call it a pass.
func macAccounts(ctx *engine.Context) []model.Finding {
	var out []model.Finding

	// --- accounts holding UID 0 ---------------------------------------------
	ids, err := runCmd(15*time.Second, "dscl", ".", "-list", "/Users", "UniqueID")
	switch {
	case err != nil || strings.TrimSpace(ids) == "":
		out = append(out, errFinding("ACC-UID0", "accounts",
			"Comptes locaux non énumérables",
			"dscl n'a rien renvoyé d'exploitable. Rien n'est affirmé sur les comptes privilégiés."))
	default:
		var uid0 []string
		parsed := 0
		for _, l := range strings.Split(ids, "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			n, convErr := strconv.Atoi(f[len(f)-1])
			if convErr != nil {
				continue
			}
			parsed++
			name := strings.Join(f[:len(f)-1], " ")
			if n == 0 && name != "root" {
				uid0 = append(uid0, fmt.Sprintf("%s (uid 0)", name))
			}
		}
		switch {
		case parsed == 0:
			out = append(out, errFinding("ACC-UID0", "accounts",
				"Liste des comptes non analysable",
				"La sortie de dscl ne contient aucun couple nom et identifiant dans la forme attendue."))
		case len(uid0) > 0:
			out = append(out, fail("ACC-UID0", "accounts",
				fmt.Sprintf("%d compte(s) autre(s) que root portent l'UID 0", len(uid0)),
				model.SevCritical,
				"Un second compte d'UID 0 est un accès root complet sous un autre nom, et c'est une façon classique de conserver un accès privilégié après une compromission.",
				"Supprimer le compte ou lui donner un identifiant ordinaire.", capEvidence(uid0)...))
		default:
			out = append(out, pass("ACC-UID0", "accounts", "Seul root porte l'UID 0"))
		}
	}

	// --- administrators ------------------------------------------------------
	if admins, aErr := runCmd(15*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); aErr == nil {
		if i := strings.Index(admins, ":"); i >= 0 {
			members := strings.Fields(admins[i+1:])
			if len(members) > 0 {
				out = append(out, info("ADM-LIST", "accounts",
					fmt.Sprintf("%d compte(s) administrateur", len(members)),
					"Chacun d'eux peut s'élever jusqu'à root. Vérifier que chacun est attendu.",
					members...))
			}
		}
	}

	// --- guest account -------------------------------------------------------
	// A writable session that needs no password widens the local attack surface
	// and is disabled by default, so finding it on means someone turned it on.
	guest, gErr := runCmd(10*time.Second, "defaults", "read",
		"/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
	if gErr == nil {
		switch strings.TrimSpace(guest) {
		case "1":
			out = append(out, fail("GUEST-ON", "accounts",
				"Le compte Invité est activé", model.SevMedium,
				"Quiconque a un accès physique obtient une session sans identifiants.",
				"Le désactiver dans Réglages Système, Utilisateurs et groupes."))
		case "0":
			out = append(out, pass("GUEST-OFF", "accounts", "Le compte Invité est désactivé"))
		}
	}
	// A missing key means the default, which is disabled; that is not worth a
	// finding either way.

	return out
}

// macRemoteAccess covers the three doors macOS can open to the network. Each is
// legitimate and each is a standing invitation once left on unattended.
func macRemoteAccess(ctx *engine.Context) []model.Finding {
	var out []model.Finding

	sshOn := false
	login, err := runCmd(20*time.Second, "systemsetup", "-getremotelogin")
	switch {
	case err != nil:
		out = append(out, errFinding("SSH-REMOTE", "ssh",
			"Réglage Remote Login illisible",
			"systemsetup a échoué, en général faute de privilèges ou d'accès complet au disque. Rien n'est affirmé sur l'exposition SSH."))
	case strings.Contains(login, "On"):
		sshOn = true
		out = append(out, fail("SSH-REMOTE", "ssh",
			"Remote Login (SSH) est activé", model.SevMedium,
			"La machine accepte des sessions SSH depuis le réseau.",
			"Le désactiver dans Réglages Système, Général, Partage, si vous n'en avez pas besoin."))
	case strings.Contains(login, "Off"):
		out = append(out, pass("SSH-REMOTE", "ssh", "Remote Login (SSH) est désactivé"))
	default:
		out = append(out, errFinding("SSH-REMOTE", "ssh",
			"Sortie Remote Login non reconnue",
			"systemsetup a répondu dans une forme que ce contrôle ne sait pas interpréter, aucune conclusion n'est tirée."))
	}

	// The daemon's configuration only matters when the daemon can be reached.
	// Penalising a disabled service produces findings nobody can act on.
	if sshOn {
		out = append(out, macSSHConfig()...)
	}

	// --- Remote Management and Screen Sharing --------------------------------
	// Both are driven by launchd, so the launchd state is the authority. The
	// spelling of that state changed across macOS releases, which is why both
	// generations are accepted below rather than one guessed at.
	if disabled, dErr := runCmdCombined(10*time.Second, "launchctl", "print-disabled", "system"); dErr == nil {
		if on, known := launchdEnabled(disabled, "com.apple.screensharing"); known && on {
			out = append(out, fail("VNC-ON", "network",
				"Screen Sharing est activé", model.SevMedium,
				"Le bureau est joignable en VNC, un protocole dont l'implémentation macOS authentifie mais ne protège pas la session de bout en bout.",
				"Le désactiver dans Réglages Système, Général, Partage, s'il ne sert pas."))
		}
	}
	if on, why := ardActive(); on {
		out = append(out, fail("RM-ON", "network",
			"Remote Management (ARD) est activé", model.SevMedium,
			"Apple Remote Desktop permet la prise en main de l'écran et l'exécution de commandes à distance. Détecté par "+why+".",
			"Disable it in System Settings > General > Sharing if unused."))
	}

	// Access granted to every local account is a much broader grant than access
	// granted to named users, so it is reported separately and more severely.
	if allUsers, aErr := runCmd(10*time.Second, "defaults", "read",
		"/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers"); aErr == nil {
		if strings.TrimSpace(allUsers) == "1" {
			out = append(out, fail("ARD-ALLUSERS", "network",
				"Remote Management est ouvert à tous les comptes locaux", model.SevHigh,
				"Chaque compte local, y compris ceux ajoutés plus tard, obtient la prise en main de l'écran et l'exécution de commandes à distance.",
				"Restreindre Remote Management à des utilisateurs nommés."))
		}
	}
	// A missing key means access was not granted to everyone, which needs no
	// finding: the earlier RM-ON check already reports that ARD is running.

	return out
}

// ardActive reports whether Apple Remote Desktop is switched on.
//
// The preference file is not the answer: on a machine with ARD active it held
// nothing but allowInsecureDH, and the ARD_AllLocalUsers key only exists when
// access was granted to everyone. The activation trigger and the running agent
// are the two signals that actually track the setting.
func ardActive() (bool, string) {
	const trigger = "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"
	if fileExists(trigger) {
		if strings.Contains(strings.ToLower(readFile(trigger)), "enabled") {
			return true, "le marqueur d'activation ARD"
		}
	}
	if out, err := runCmd(10*time.Second, "pgrep", "-x", "ARDAgent"); err == nil && strings.TrimSpace(out) != "" {
		return true, "un processus ARDAgent en cours"
	}
	return false, ""
}

// launchdEnabled reads a service's state out of "launchctl print-disabled".
//
// The output is a disabled-list, and its spelling changed: older macOS printed
// "=> false" for a service that is not disabled, current macOS prints
// "=> enabled". Reading only one of the two silently reports every service as
// off, which is how Screen Sharing went unnoticed while it was listening on
// port 5900.
func launchdEnabled(out, label string) (enabled bool, known bool) {
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, label) {
			continue
		}
		low := strings.ToLower(l)
		switch {
		case strings.Contains(low, "=> enabled"), strings.Contains(low, "=> false"):
			return true, true
		case strings.Contains(low, "=> disabled"), strings.Contains(low, "=> true"):
			return false, true
		}
	}
	return false, false
}

// macSSHConfig reads sshd_config for the settings that matter most. It mirrors
// the Linux checks so the same finding IDs mean the same thing on both.
func macSSHConfig() []model.Finding {
	const path = "/etc/ssh/sshd_config"
	if !fileExists(path) {
		return []model.Finding{info("SSH-NOCONF", "ssh", "Aucun sshd_config trouvé",
			"Remote Login est actif mais le fichier de configuration est absent. Le démon tourne sur ses valeurs par défaut.")}
	}
	lines := readLines(path)
	if len(lines) == 0 {
		return []model.Finding{errFinding("SSH-NOCONF", "ssh",
			"sshd_config illisible",
			"Remote Login est actif mais sa configuration n'a pas pu être lue, rien n'est donc affirmé à son sujet.")}
	}

	value := func(key string) string {
		want := strings.ToLower(key)
		val := ""
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			f := strings.Fields(l)
			if len(f) < 2 || strings.ToLower(f[0]) != want {
				continue
			}
			val = strings.ToLower(f[1]) // last directive wins, as sshd does
		}
		return val
	}

	var out []model.Finding
	if v := value("PermitRootLogin"); v == "yes" {
		out = append(out, fail("SSH-ROOT", "ssh",
			"SSH autorise la connexion root", model.SevHigh,
			"PermitRootLogin yes laisse attaquer root directement, sans trace de qui s'est élevé.",
			"Poser PermitRootLogin no, ou prohibit-password au minimum."))
	}
	if v := value("PasswordAuthentication"); v == "yes" {
		out = append(out, fail("SSH-PWAUTH", "ssh",
			"L'authentification SSH par mot de passe est activée", model.SevMedium,
			"Un mot de passe se devine à grande échelle, une clé non.",
			"Poser PasswordAuthentication no une fois la connexion par clé opérationnelle."))
	}
	if v := value("PermitEmptyPasswords"); v == "yes" {
		out = append(out, fail("SSH-EMPTYPW", "ssh",
			"SSH autorise les mots de passe vides", model.SevCritical,
			"Tout compte sans mot de passe devient un point d'entrée distant.",
			"Poser PermitEmptyPasswords no."))
	}
	if len(out) == 0 {
		out = append(out, pass("SSH-CONF", "ssh", "La configuration sshd ne présente aucune faiblesse manifeste"))
	}
	return out
}

// macSystemIntegrity covers the protections that make macOS itself hard to
// modify. They are on by default, so finding one off means it was turned off.
func macSystemIntegrity(ctx *engine.Context) []model.Finding {
	var out []model.Finding

	// --- signed system volume ------------------------------------------------
	// Distinct from SIP: SSV cryptographically seals the system volume, so
	// tampering with a system binary makes the machine refuse to boot.
	ssv, err := runCmd(10*time.Second, "csrutil", "authenticated-root", "status")
	low := strings.ToLower(ssv)
	switch {
	case err != nil && ssv == "":
		out = append(out, errFinding("SSV-STATE", "hardening",
			"État du volume système scellé illisible",
			"csrutil n'a rien renvoyé d'exploitable, rien n'est donc affirmé."))
	case strings.Contains(low, "disabled"):
		out = append(out, fail("SSV-OFF", "hardening",
			"Le volume système scellé est désactivé", model.SevHigh,
			"Le sceau qui rend les binaires système immuables a été retiré. C'est un acte délibéré, et un préalable à toute altération durable au niveau système.",
			"Le réactiver depuis Recovery avec csrutil authenticated-root enable."))
	case strings.Contains(low, "enabled"):
		out = append(out, pass("SSV-ON", "hardening", "Le volume système scellé est actif"))
	default:
		out = append(out, errFinding("SSV-STATE", "hardening",
			"Sortie du volume système scellé non reconnue",
			"csrutil a répondu dans une forme que ce contrôle ne sait pas interpréter."))
	}

	// --- automatic updates ---------------------------------------------------
	readFlag := func(key string) (string, bool) {
		v, rErr := runCmd(10*time.Second, "defaults", "read",
			"/Library/Preferences/com.apple.SoftwareUpdate", key)
		if rErr != nil {
			return "", false
		}
		return strings.TrimSpace(v), true
	}
	if v, ok := readFlag("AutomaticCheckEnabled"); ok && v == "0" {
		out = append(out, fail("UPD-NOCHECK", "hardening",
			"La recherche automatique de mises à jour est désactivée", model.SevMedium,
			"La machine n'apprendra pas qu'un correctif existe.",
			"Réactiver la recherche dans Réglages Système, Général, Mise à jour de logiciels."))
	}
	if v, ok := readFlag("CriticalUpdateInstall"); ok && v == "0" {
		out = append(out, fail("UPD-NOCRITICAL", "hardening",
			"L'installation automatique des correctifs de sécurité critiques est désactivée", model.SevMedium,
			"Les définitions XProtect et de suppression de logiciels malveillants ne se mettront pas à jour d'elles-mêmes.",
			"Activer les réponses de sécurité dans Réglages Système, Général, Mise à jour de logiciels."))
	}

	return out
}

// macSystemExtensions covers the modern replacement for kernel extensions.
// Checking only kexts on a current macOS leaves the actual extension mechanism
// unexamined while reporting a clean kernel.
func macSystemExtensions(ctx *engine.Context) []model.Finding {
	if !cmdAvailable("systemextensionsctl") {
		return nil
	}
	out, err := runCmdCombined(20*time.Second, "systemextensionsctl", "list")
	if err != nil && strings.TrimSpace(out) == "" {
		return []model.Finding{errFinding("SYSEXT-LIST", "kernel",
			"Extensions système non énumérables",
			"systemextensionsctl n'a rien renvoyé d'exploitable, rien n'est donc affirmé sur les extensions chargées.")}
	}

	var active []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		// Rows carry a bracketed state such as [activated enabled]. Anything
		// without one is a header or a total.
		if !strings.Contains(l, "[activated") {
			continue
		}
		active = append(active, trunc(l, 140))
	}
	if len(active) == 0 {
		return []model.Finding{pass("SYSEXT-NONE", "kernel", "Aucune extension système tierce n'est active")}
	}
	return []model.Finding{info("SYSEXT-ACTIVE", "kernel",
		fmt.Sprintf("%d extension(s) système active(s)", len(active)),
		"Une extension système s'exécute avec de hauts privilèges et peut inspecter le trafic réseau ou filtrer les fichiers. Vérifier que chaque éditeur est attendu.",
		capEvidence(active)...)}
}
