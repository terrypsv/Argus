//go:build linux

package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// osChecks returns the Linux check set.
func osChecks() []check {
	return []check{
		{Name: "privilege", Category: "system", Fn: privilegeCheck},
		{Name: "kernel-hardening", Category: "kernel", Fn: kernelHardeningCheck},
		{Name: "kernel-taint", Category: "kernel", Fn: kernelTaintCheck},
		{Name: "ld-preload", Category: "kernel", Fn: ldPreloadCheck},
		{Name: "accounts", Category: "accounts", Fn: accountsCheck},
		{Name: "ssh-hardening", Category: "ssh", Fn: sshHardeningCheck},
		{Name: "suid", Category: "disk", Fn: suidCheck},
		{Name: "world-writable", Category: "disk", Fn: worldWritableCheck},
		{Name: "mount-flags", Category: "disk", Fn: mountFlagsCheck},
		{Name: "disk-usage", Category: "disk", Fn: diskUsageCheck},
		{Name: "cron-persistence", Category: "persistence", Fn: cronCheck},
		{Name: "systemd-persistence", Category: "persistence", Fn: systemdCheck},
		{Name: "listening-ports", Category: "network", Fn: portsCheck},
		{Name: "firewall", Category: "network", Fn: firewallCheck},
		{Name: "process-anomalies", Category: "process", Fn: processCheck},
		{Name: "package-verify", Category: "integrity", Fn: pkgVerifyCheck},
		{Name: "root-certificates", Category: "certificates", Fn: certStoreCheck},
	}
}

// DefaultCriticalPaths are the files hashed by `argus baseline` on Linux.
func DefaultCriticalPaths() []string {
	return []string{
		"/bin/ls", "/bin/ps", "/bin/bash", "/bin/sh", "/bin/login",
		"/usr/bin/ls", "/usr/bin/ps", "/usr/bin/bash",
		"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/find",
		"/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/curl", "/usr/bin/wget",
		"/usr/sbin/sshd", "/sbin/init",
		"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts",
		"/etc/pam.d/sshd", "/etc/crontab",
	}
}

func privilegeCheck(ctx *engine.Context) []model.Finding {
	if os.Geteuid() == 0 {
		return []model.Finding{info("PRIV-ROOT", "system",
			"Exécution en root", "Couverture complète des contrôles.")}
	}
	return []model.Finding{info("PRIV-USER", "system",
		"Exécution sans les droits root",
		"Certains contrôles sont limités, dont le fichier shadow, les règles de pare-feu et les tables cron. Relancer avec sudo pour une couverture complète.")}
}

// --- kernel hardening ---------------------------------------------------------

func sysctlRaw(name string) (string, bool) {
	p := "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func kernelHardeningCheck(ctx *engine.Context) []model.Finding {
	type rule struct {
		key, label string
		ok         func(v string) bool
		sev        model.Severity
		fix        string
	}
	geInt := func(min int) func(string) bool {
		return func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= min }
	}
	eqStr := func(want string) func(string) bool {
		return func(v string) bool { return v == want }
	}
	rules := []rule{
		{"kernel.randomize_va_space", "Randomisation complète de l'espace d'adressage", eqStr("2"), model.SevHigh,
			"Poser kernel.randomize_va_space=2 dans /etc/sysctl.d/."},
		{"kernel.kptr_restrict", "Masquage des adresses du noyau", geInt(1), model.SevMedium,
			"Poser kernel.kptr_restrict=1 pour masquer les adresses du noyau aux utilisateurs ordinaires."},
		{"kernel.dmesg_restrict", "Restriction de dmesg", eqStr("1"), model.SevLow,
			"Poser kernel.dmesg_restrict=1."},
		{"kernel.yama.ptrace_scope", "Restriction de ptrace", geInt(1), model.SevMedium,
			"Poser kernel.yama.ptrace_scope=1 pour bloquer l'injection de mémoire entre processus."},
		// 0 = unprivileged BPF allowed. 1 = disabled permanently, 2 = disabled
		// but re-enablable by root. Both 1 and 2 mean it is currently disabled.
		{"kernel.unprivileged_bpf_disabled", "eBPF non privilégié désactivé", geInt(1), model.SevMedium,
			"Poser kernel.unprivileged_bpf_disabled=1."},
		{"fs.protected_hardlinks", "Protection des liens physiques", eqStr("1"), model.SevLow,
			"Poser fs.protected_hardlinks=1."},
		{"fs.protected_symlinks", "Protection des liens symboliques", eqStr("1"), model.SevLow,
			"Poser fs.protected_symlinks=1."},
		{"net.ipv4.conf.all.rp_filter", "Filtrage par chemin inverse", geInt(1), model.SevLow,
			"Poser net.ipv4.conf.all.rp_filter=1 pour limiter l'usurpation d'adresse IP."},
	}

	var out []model.Finding
	okCount := 0
	for _, r := range rules {
		v, present := sysctlRaw(r.key)
		if !present {
			continue // sysctl not applicable on this kernel
		}
		if r.ok(v) {
			okCount++
			continue
		}
		out = append(out, fail("KRN-"+strings.ToUpper(strings.ReplaceAll(r.key, ".", "-")),
			"kernel", r.label+" : absent ou insuffisant", r.sev,
			fmt.Sprintf("%s = %q", r.key, v), r.fix))
	}
	if len(out) == 0 && okCount > 0 {
		out = append(out, pass("KRN-HARDENING", "kernel",
			fmt.Sprintf("Durcissement du noyau complet (%d paramètres vérifiés)", okCount)))
	}
	return out
}

func kernelTaintCheck(ctx *engine.Context) []model.Finding {
	v, ok := sysctlRaw("kernel.tainted")
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n == 0 {
		return []model.Finding{pass("KRN-TAINT", "kernel", "Noyau non souillé")}
	}
	bits := map[int]string{
		1 << 0:  "module propriétaire chargé",
		1 << 4:  "erreur matérielle signalée",
		1 << 9:  "incident noyau",
		1 << 11: "contournement de micrologiciel",
		1 << 12: "module hors arborescence chargé",
		1 << 13: "module non signé chargé",
	}
	var flags []string
	sev := model.SevLow
	for bit, label := range bits {
		if n&bit != 0 {
			flags = append(flags, label)
			if bit == 1<<12 || bit == 1<<13 {
				sev = model.SevMedium
			}
		}
	}
	sort.Strings(flags)
	return []model.Finding{fail("KRN-TAINT", "kernel",
		"Noyau souillé", sev,
		fmt.Sprintf("souillure=%d (%s)", n, strings.Join(flags, ", ")),
		"Un module hors arborescence ou non signé peut dissimuler du code malveillant. Vérifier chaque module étranger à la distribution.",
		flags...)}
}

func ldPreloadCheck(ctx *engine.Context) []model.Finding {
	var out []model.Finding
	if fileExists("/etc/ld.so.preload") {
		out = append(out, fail("KRN-LDPRELOAD", "kernel",
			"/etc/ld.so.preload est présent", model.SevHigh,
			"Le préchargement global de bibliothèques est un point d'accroche classique des rootkits en espace utilisateur.",
			"Confirmer que chaque bibliothèque listée est légitime. Une entrée inattendue signale un rootkit probable.",
			readLines("/etc/ld.so.preload")...))
	}
	for _, l := range readLines("/etc/environment") {
		if strings.HasPrefix(strings.ToUpper(l), "LD_PRELOAD") {
			out = append(out, fail("KRN-ENVPRELOAD", "kernel",
				"LD_PRELOAD défini globalement dans /etc/environment", model.SevHigh,
				l, "Retirer, sauf si vous savez exactement pourquoi cette valeur est là."))
		}
	}
	if len(out) == 0 {
		out = append(out, pass("KRN-LDPRELOAD", "kernel", "Aucun préchargement global de bibliothèque"))
	}
	return out
}

// --- accounts -----------------------------------------------------------------

func accountsCheck(ctx *engine.Context) []model.Finding {
	var out []model.Finding

	// UID 0 accounts other than root.
	var uid0 []string
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) < 3 {
			continue
		}
		if f[2] == "0" && f[0] != "root" {
			uid0 = append(uid0, l)
		}
	}
	if len(uid0) > 0 {
		out = append(out, fail("ACC-UID0", "accounts",
			"Compte(s) autre(s) que root avec l'UID 0", model.SevCritical,
			"Un compte d'UID 0 dispose des pleins privilèges root. C'est la porte dérobée du manuel.",
			"Supprimer ou corriger le compte immédiatement.", uid0...))
	} else {
		out = append(out, pass("ACC-UID0", "accounts", "Seul root porte l'UID 0"))
	}

	// Empty passwords in /etc/shadow (root only).
	shadow := readLines("/etc/shadow")
	if len(shadow) == 0 {
		out = append(out, info("ACC-SHADOW", "accounts",
			"/etc/shadow illisible", "Relancer en root pour vérifier les mots de passe vides."))
	} else {
		var empty []string
		for _, l := range shadow {
			f := strings.Split(l, ":")
			if len(f) >= 2 && f[1] == "" {
				empty = append(empty, f[0])
			}
		}
		if len(empty) > 0 {
			out = append(out, fail("ACC-EMPTYPW", "accounts",
				"Compte(s) sans mot de passe", model.SevCritical,
				"Ces comptes permettent d'ouvrir une session sans aucun mot de passe.",
				"Les verrouiller avec passwd -l <utilisateur>, ou leur poser un mot de passe solide.", empty...))
		} else {
			out = append(out, pass("ACC-EMPTYPW", "accounts", "Aucun compte sans mot de passe"))
		}
	}
	return out
}

// --- ssh ----------------------------------------------------------------------

// sshdRunning reports whether an sshd process is actually alive. Scanning
// /proc avoids depending on systemd being the init system.
func sshdRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm := strings.TrimSpace(readFile(filepath.Join("/proc", e.Name(), "comm")))
		if comm == "sshd" {
			return true
		}
	}
	return false
}

func sshHardeningCheck(ctx *engine.Context) []model.Finding {
	const cfg = "/etc/ssh/sshd_config"
	if !fileExists(cfg) {
		return []model.Finding{info("SSH-NONE", "ssh", "Aucun sshd_config trouvé", "Le serveur OpenSSH n'est pas installé.")}
	}
	// Effective value = last non-comment occurrence.
	vals := map[string]string{}
	for _, l := range readLines(cfg) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.Fields(l)
		if len(parts) >= 2 {
			vals[strings.ToLower(parts[0])] = strings.ToLower(parts[1])
		}
	}

	// A weak sshd_config on a host where sshd is not running is not an exposure:
	// report it, but do not penalise the score for a service nobody can reach.
	running := sshdRunning()

	var out []model.Finding
	add := func(id, title string, sev model.Severity, detail, fix string) {
		if !running {
			out = append(out, info(id, "ssh", title+" (sshd à l'arrêt)",
				detail+" - le service ne tourne pas actuellement, ce n'est donc pas une exposition active. "+fix))
			return
		}
		out = append(out, fail(id, "ssh", title, sev, detail, fix))
	}
	if v := vals["permitrootlogin"]; v == "yes" {
		add("SSH-ROOT", "SSH autorise la connexion root par mot de passe", model.SevHigh,
			"PermitRootLogin yes", "Poser PermitRootLogin prohibit-password, ou no.")
	}
	if v, ok := vals["passwordauthentication"]; !ok || v == "yes" {
		add("SSH-PWAUTH", "Authentification SSH par mot de passe activée", model.SevMedium,
			"PasswordAuthentication n'est pas désactivé", "Préférer les clés, en posant PasswordAuthentication no.")
	}
	if vals["permitemptypasswords"] == "yes" {
		add("SSH-EMPTYPW", "SSH autorise les mots de passe vides", model.SevCritical,
			"PermitEmptyPasswords yes", "Poser PermitEmptyPasswords no.")
	}
	if vals["protocol"] == "1" {
		add("SSH-PROTO1", "Protocole SSH 1 activé", model.SevCritical,
			"Protocol 1", "Retirer la directive Protocol, seule la version 2 est sûre.")
	}
	if vals["x11forwarding"] == "yes" {
		add("SSH-X11", "Redirection X11 activée dans SSH", model.SevLow,
			"X11Forwarding yes", "Désactiver sauf besoin avéré.")
	}
	if len(out) == 0 {
		out = append(out, pass("SSH-OK", "ssh", "sshd_config satisfait les contrôles de durcissement"))
	}
	return out
}

// --- SUID / world-writable ----------------------------------------------------

func scanRoots(ctx *engine.Context) []string {
	if len(ctx.Config.ScanRoots) > 0 {
		return ctx.Config.ScanRoots
	}
	return []string{"/usr", "/bin", "/sbin", "/etc", "/opt", "/home", "/var", "/tmp", "/dev/shm", "/run"}
}

func suspiciousLocation(path string) bool {
	return containsAny(path, "/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/run/shm/")
}

func suidCheck(ctx *engine.Context) []model.Finding {
	if ctx.Config.Quick {
		return []model.Finding{info("SUID-SKIP", "disk", "Recherche des binaires SUID ignorée (mode rapide)", "")}
	}
	var suspicious, all []string
	walkLimited(scanRoots(ctx), 400000, func(path string, d fs.DirEntry) {
		if d.IsDir() {
			return
		}
		fi, err := d.Info()
		if err != nil {
			return
		}
		m := fi.Mode()
		if m&os.ModeSetuid == 0 && m&os.ModeSetgid == 0 {
			return
		}
		all = append(all, path)
		if suspiciousLocation(path) {
			suspicious = append(suspicious, path)
		}
	})

	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("SUID-SUSP", "disk",
			"Binaire SUID/SGID dans un emplacement temporaire ou modifiable", model.SevHigh,
			"Un binaire SUID à cet endroit est une voie classique d'élévation de privilèges.",
			"Examiner chacun, et retirer le bit SUID avec chmod -s s'il n'est pas nécessaire.",
			capEvidence(suspicious)...))
	}
	out = append(out, info("SUID-INV", "disk",
		fmt.Sprintf("%d binaire(s) SUID/SGID trouvé(s)", len(all)),
		"Passer l'inventaire en revue et le comparer à une machine de référence.",
		capEvidence(all)...))
	return out
}

func worldWritableCheck(ctx *engine.Context) []model.Finding {
	if ctx.Config.Quick {
		return []model.Finding{info("WW-SKIP", "disk", "Recherche des fichiers modifiables par tous ignorée (mode rapide)", "")}
	}
	systemDirs := []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/boot"}
	var wwSystem, wwDirNoSticky []string
	walkLimited(scanRoots(ctx), 400000, func(path string, d fs.DirEntry) {
		fi, err := d.Info()
		if err != nil {
			return
		}
		m := fi.Mode()
		if m&os.ModeSymlink != 0 {
			return
		}
		if m.Perm()&0o002 == 0 {
			return
		}
		if d.IsDir() {
			if m&os.ModeSticky == 0 {
				wwDirNoSticky = append(wwDirNoSticky, path)
			}
			return
		}
		for _, sd := range systemDirs {
			if strings.HasPrefix(path, sd+"/") || path == sd {
				wwSystem = append(wwSystem, path)
				break
			}
		}
	})

	var out []model.Finding
	if len(wwSystem) > 0 {
		out = append(out, fail("WW-SYSTEM", "disk",
			"Fichier(s) modifiable(s) par tous dans un répertoire système", model.SevHigh,
			"N'importe quel utilisateur local peut les modifier, ce qui en fait un vecteur idéal de persistance et d'altération.",
			"Resserrer les permissions avec chmod o-w.", capEvidence(wwSystem)...))
	}
	if len(wwDirNoSticky) > 0 {
		out = append(out, fail("WW-DIR", "disk",
			"Répertoire modifiable par tous sans bit collant", model.SevLow,
			"Les utilisateurs peuvent y supprimer ou renommer les fichiers des autres.",
			"Poser le bit collant avec chmod +t, ou restreindre l'écriture.", capEvidence(wwDirNoSticky)...))
	}
	if len(out) == 0 {
		out = append(out, pass("WW-OK", "disk", "Aucune entrée modifiable par tous dangereuse"))
	}
	return out
}

func mountFlagsCheck(ctx *engine.Context) []model.Finding {
	type mnt struct{ point, opts string }
	var mounts []mnt
	for _, l := range readLines("/proc/mounts") {
		f := strings.Fields(l)
		if len(f) >= 4 {
			mounts = append(mounts, mnt{f[1], f[3]})
		}
	}
	want := []string{"/tmp", "/dev/shm", "/var/tmp"}
	var out []model.Finding
	for _, target := range want {
		var found *mnt
		for i := range mounts {
			if mounts[i].point == target {
				found = &mounts[i]
				break
			}
		}
		if found == nil {
			out = append(out, fail("MNT-"+strings.ToUpper(sanitize(target)), "disk",
				target+" n'est pas un montage séparé", model.SevLow,
				"Impossible d'appliquer noexec ou nosuid à "+target+".",
				"Envisager un montage dédié avec noexec, nosuid et nodev."))
			continue
		}
		if !strings.Contains(found.opts, "noexec") {
			out = append(out, fail("MNT-NOEXEC-"+strings.ToUpper(sanitize(target)), "disk",
				target+" est monté sans noexec", model.SevMedium,
				"options : "+found.opts,
				"Remonter "+target+" avec noexec pour empêcher l'exécution de charges déposées."))
		}
	}
	if len(out) == 0 {
		out = append(out, pass("MNT-OK", "disk", "Systèmes de fichiers temporaires montés avec des options sûres"))
	}
	return out
}

// --- persistence --------------------------------------------------------------

func cronCheck(ctx *engine.Context) []model.Finding {
	sources := []string{"/etc/crontab"}
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				sources = append(sources, filepath.Join(dir, e.Name()))
			}
		}
	}
	var suspicious []string
	total := 0
	for _, src := range sources {
		for _, l := range readLines(src) {
			if strings.HasPrefix(l, "#") {
				continue
			}
			total++
			if containsAny(l, suspiciousCmdTokens...) || containsAny(l, suspiciousPathTokens...) {
				suspicious = append(suspicious, src+": "+trunc(l, 120))
			}
		}
	}
	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("CRON-SUSP", "persistence",
			"Entrée(s) cron suspecte(s)", model.SevHigh,
			"Une tâche cron qui télécharge ou exécute depuis un répertoire temporaire est un moyen de persistance courant.",
			"Examiner chaque ligne, et retirer ce que vous n'avez pas créé.", capEvidence(suspicious)...))
	} else {
		out = append(out, pass("CRON-OK", "persistence",
			fmt.Sprintf("Aucune entrée cron suspecte (%d examinées)", total)))
	}
	return out
}

func systemdCheck(ctx *engine.Context) []model.Finding {
	dirs := []string{"/etc/systemd/system", "/run/systemd/system",
		filepath.Join(os.Getenv("HOME"), ".config/systemd/user")}
	var suspicious []string
	total := 0
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".service") {
				return nil
			}
			total++
			for _, l := range readLines(path) {
				if strings.HasPrefix(l, "ExecStart") {
					if containsAny(l, suspiciousPathTokens...) || containsAny(l, suspiciousCmdTokens...) {
						suspicious = append(suspicious, path+": "+trunc(l, 120))
					}
				}
			}
			return nil
		})
	}
	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("SVC-SUSP", "persistence",
			"Service(s) systemd suspect(s)", model.SevHigh,
			"Un service dont ExecStart pointe vers un chemin temporaire ou modifiable est un indice fort de persistance.",
			"Inspecter les fichiers d'unité et désactiver tout ce qui est inattendu.", capEvidence(suspicious)...))
	} else {
		out = append(out, pass("SVC-OK", "persistence",
			fmt.Sprintf("Aucun service systemd suspect (%d examinés)", total)))
	}
	return out
}

// --- network ------------------------------------------------------------------

type listener struct {
	port  int
	allIf bool
	proto string
}

// tcpListenState is the hex state of a socket in LISTEN in /proc/net/tcp.
const tcpListenState = "0A"

// linuxEphemeralFloor is the bottom of Linux's default local port range. A UDP
// socket bound above it is a client's source port, not a service. TCP needs no
// such rule because a client socket is never in LISTEN.
const linuxEphemeralFloor = 32768

// parseProcNet reads a /proc/net/{tcp,udp}[6] table. listenState is the hex
// state a socket must be in to count; an empty value accepts every state, which
// is what UDP needs since it has no listening state.
//
// The boolean distinguishes "the table was readable and held no sockets" from
// "the table could not be read". Reporting zero open ports because the check
// failed is worse than reporting nothing: it is a false all-clear.
func parseProcNet(path, proto, listenState string) ([]listener, bool) {
	if !fileExists(path) {
		return nil, false
	}
	lines := readLines(path)
	if len(lines) == 0 {
		return nil, false // present but unreadable: /proc tables always carry a header
	}
	udp := strings.HasPrefix(proto, "udp")

	var out []listener
	for i, l := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if listenState != "" && f[3] != listenState {
			continue
		}
		la := f[1]
		colon := strings.LastIndex(la, ":")
		if colon < 0 {
			continue
		}
		addrHex, portHex := la[:colon], la[colon+1:]
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port == 0 {
			continue
		}
		if udp && port >= linuxEphemeralFloor {
			continue // a client's source port, not a listening service
		}
		all := strings.Trim(addrHex, "0") == "" // 0.0.0.0 or ::
		out = append(out, listener{port: int(port), allIf: all, proto: proto})
	}
	return out, true
}

// family collapses tcp/tcp6 and udp/udp6 for risk lookups.
func family(proto string) string {
	if strings.HasPrefix(proto, "udp") {
		return "udp"
	}
	return "tcp"
}

func portsCheck(ctx *engine.Context) []model.Finding {
	tcp4, okTCP4 := parseProcNet("/proc/net/tcp", "tcp", tcpListenState)
	tcp6, okTCP6 := parseProcNet("/proc/net/tcp6", "tcp6", tcpListenState)
	udp4, _ := parseProcNet("/proc/net/udp", "udp", "")
	udp6, _ := parseProcNet("/proc/net/udp6", "udp6", "")

	if !okTCP4 && !okTCP6 {
		return []model.Finding{errFinding("NET-LISTEN", "network",
			"Sockets en écoute non énumérables",
			"Ni /proc/net/tcp ni /proc/net/tcp6 n'ont pu être lus. Annoncer zéro port ouvert serait une fausse assurance, donc rien n'est affirmé. Relancer avec des privilèges suffisants.")}
	}

	var ls []listener
	ls = append(ls, tcp4...)
	ls = append(ls, tcp6...)
	ls = append(ls, udp4...)
	ls = append(ls, udp6...)

	risky := map[string]struct {
		sev   model.Severity
		label string
	}{
		"tcp/23":    {model.SevHigh, "telnet, en clair"},
		"tcp/21":    {model.SevMedium, "ftp, en clair"},
		"tcp/513":   {model.SevMedium, "rlogin"},
		"tcp/514":   {model.SevMedium, "rsh"},
		"tcp/6379":  {model.SevHigh, "redis, souvent sans authentification"},
		"tcp/27017": {model.SevHigh, "mongodb"},
		"tcp/9200":  {model.SevMedium, "elasticsearch"},
		"tcp/3306":  {model.SevMedium, "mysql exposé"},
		"tcp/5432":  {model.SevMedium, "postgres exposé"},
		"udp/69":    {model.SevHigh, "tftp, sans authentification"},
		"udp/161":   {model.SevMedium, "snmp, souvent avec les communautés par défaut"},
		"udp/623":   {model.SevHigh, "ipmi, rarement mis à jour"},
		"udp/137":   {model.SevMedium, "service de noms netbios"},
		"udp/138":   {model.SevMedium, "service de datagrammes netbios"},
		"udp/111":   {model.SevMedium, "rpcbind"},
	}

	var out []model.Finding
	seen := map[string]bool{}
	var inventory []string
	for _, l := range ls {
		scope := "boucle locale ou autre"
		if l.allIf {
			scope = "toutes interfaces"
		}
		inventory = append(inventory, fmt.Sprintf("%s/%d (%s)", l.proto, l.port, scope))

		key := fmt.Sprintf("%s/%d", family(l.proto), l.port)
		if r, ok := risky[key]; ok && l.allIf && !seen[key] {
			seen[key] = true
			out = append(out, fail(
				"NET-PORT-"+strings.ToUpper(family(l.proto))+"-"+strconv.Itoa(l.port), "network",
				fmt.Sprintf("Service à risque sur le port %s %d, exposé sur toutes les interfaces", family(l.proto), l.port),
				r.sev, r.label, "Restreindre l'écoute à la boucle locale, ajouter une authentification, ou filtrer le port."))
		}
	}
	sort.Strings(inventory)
	inventory = uniqueStrings(inventory)
	out = append(out, info("NET-LISTEN", "network",
		fmt.Sprintf("%d socket(s) en écoute, TCP et UDP", len(inventory)),
		"Chaque port ouvert est une surface d'attaque. Vérifier que chacun est attendu.", capEvidence(inventory)...))
	return out
}

func firewallCheck(ctx *engine.Context) []model.Finding {
	// ufw
	if cmdAvailable("ufw") {
		if out, err := runCmd(4*time.Second, "ufw", "status"); err == nil {
			if strings.Contains(strings.ToLower(out), "status: active") {
				return []model.Finding{pass("FW-UFW", "network", "Le pare-feu ufw est actif")}
			}
		}
	}
	// nftables
	if cmdAvailable("nft") {
		if out, err := runCmd(4*time.Second, "nft", "list", "ruleset"); err == nil && strings.TrimSpace(out) != "" {
			if containsAny(out, "drop", "reject") {
				return []model.Finding{pass("FW-NFT", "network", "Un jeu de règles nftables est en place")}
			}
		}
	}
	// iptables
	if cmdAvailable("iptables") {
		if out, err := runCmd(4*time.Second, "iptables", "-S"); err == nil {
			if containsAny(out, "-j DROP", "-j REJECT") {
				return []model.Finding{pass("FW-IPT", "network", "Des règles de filtrage iptables sont en place")}
			}
			return []model.Finding{fail("FW-NONE", "network",
				"Aucune règle de pare-feu local détectée", model.SevMedium,
				"iptables n'affiche que des politiques par défaut en acceptation.",
				"Activer ufw ou nftables, ou ajouter des règles iptables pour limiter l'exposition entrante.")}
		}
	}
	return []model.Finding{info("FW-UNKNOWN", "network",
		"État du pare-feu indéterminable",
		"Relancer en root. Aucun outil de pare-feu exploitable n'a répondu.")}
}

// --- process / rootkit heuristics --------------------------------------------

// systemBinaryPrefixes are package-managed locations. A binary that vanishes
// from one of these while its process keeps running is almost always the result
// of a package upgrade, not of an attacker.
var systemBinaryPrefixes = []string{
	"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/snap/", "/nix/store/",
}

func processCheck(ctx *engine.Context) []model.Finding {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []model.Finding{errFinding("PROC-READ", "process", "/proc illisible", err.Error())}
	}
	var memfd, deletedSuspect, deletedSystem, tempExec []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue // not a PID
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue // process gone or no permission
		}
		entry := e.Name() + " -> " + exe

		// A memfd-backed image never touched the disk. This is the actual
		// fileless-execution technique, and it has almost no benign use.
		if strings.Contains(exe, "memfd:") {
			memfd = append(memfd, entry)
			continue
		}

		if strings.HasSuffix(exe, " (deleted)") {
			path := strings.TrimSuffix(exe, " (deleted)")
			if hasAnyPrefix(path, systemBinaryPrefixes...) {
				deletedSystem = append(deletedSystem, entry)
			} else {
				deletedSuspect = append(deletedSuspect, entry)
			}
			continue
		}
		if containsAny(exe, suspiciousPathTokens...) {
			tempExec = append(tempExec, entry)
		}
	}

	var out []model.Finding
	if len(memfd) > 0 {
		out = append(out, fail("PROC-MEMFD", "process",
			"Processus s'exécutant depuis un fichier mémoire anonyme", model.SevCritical,
			"Un exécutable adossé à memfd n'a jamais existé sur le disque. C'est la signature d'une exécution sans fichier.",
			"Investiguer immédiatement avec ls -l /proc/<pid>/exe, cat /proc/<pid>/maps et ss -tnp.",
			capEvidence(memfd)...))
	}
	if len(deletedSuspect) > 0 {
		out = append(out, fail("PROC-DELETED", "process",
			"Processus s'exécutant depuis un binaire supprimé hors système", model.SevHigh,
			"L'image a été retirée du disque et ne provenait pas d'un emplacement géré par le gestionnaire de paquets.",
			"Inspecter ces processus avec ls -l /proc/<pid>/exe et cat /proc/<pid>/maps avant de les arrêter.",
			capEvidence(deletedSuspect)...))
	}
	if len(tempExec) > 0 {
		out = append(out, fail("PROC-TEMPEXEC", "process",
			"Processus s'exécutant depuis un répertoire temporaire", model.SevHigh,
			"Un service légitime tourne rarement depuis /tmp ou /dev/shm.",
			"Identifier le parent et l'origine de chaque processus.", capEvidence(tempExec)...))
	}
	if len(deletedSystem) > 0 {
		out = append(out, info("PROC-UPGRADED", "process",
			fmt.Sprintf("%d processus exécutant encore un binaire système remplacé", len(deletedSystem)),
			"Leur image sur disque a été remplacée par une mise à jour de paquet, ce qui est attendu sur une distribution en flux continu. Redémarrer les services, ou la machine, pour qu'ils exécutent le code corrigé.",
			capEvidence(deletedSystem)...))
	}
	if len(out) == 0 {
		out = append(out, pass("PROC-OK", "process", "Aucune anomalie de processus manifeste"))
	}
	return out
}
