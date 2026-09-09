//go:build windows

package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

func osChecks() []check {
	return []check{
		{Name: "privilege", Category: "system", Fn: winPrivilege},
		{Name: "defender", Category: "antivirus", Fn: winDefender},
		{Name: "firewall", Category: "network", Fn: winFirewall},
		{Name: "uac", Category: "hardening", Fn: winUAC},
		{Name: "smb1", Category: "hardening", Fn: winSMB1},
		{Name: "rdp", Category: "network", Fn: winRDP},
		{Name: "bitlocker", Category: "disk", Fn: winBitLocker},
		{Name: "disk-usage", Category: "disk", Fn: diskUsageCheck},
		{Name: "listening-ports", Category: "network", Fn: winPorts},
		{Name: "startup", Category: "persistence", Fn: winStartup},
		{Name: "scheduled-tasks", Category: "persistence", Fn: winTasks},
		{Name: "local-admins", Category: "accounts", Fn: winAdmins},
		{Name: "root-certificates", Category: "certificates", Fn: certStoreCheck},
	}
}

// DefaultCriticalPaths are hashed by `argus baseline` on Windows.
func DefaultCriticalPaths() []string {
	return []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\svchost.exe`,
		`C:\Windows\System32\lsass.exe`,
		`C:\Windows\System32\services.exe`,
		`C:\Windows\System32\winlogon.exe`,
		`C:\Windows\System32\kernel32.dll`,
		`C:\Windows\System32\drivers\etc\hosts`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\explorer.exe`,
	}
}

var ps = []string{"-NoProfile", "-NonInteractive", "-Command"}

func psCmd(script string) (string, error) {
	args := append(append([]string{}, ps...), script)
	return runCmd(15*time.Second, "powershell", args...)
}

func lower(s string) string { return strings.ToLower(s) }

// suspicious tokens for Windows persistence artefacts.
var winSuspicious = []string{`\temp\`, `\appdata\`, `\users\public\`, `\programdata\`,
	"-enc", "-encodedcommand", "frombase64", "iex ", "invoke-expression",
	"mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "downloadstring"}

func winPrivilege(ctx *engine.Context) []model.Finding {
	out, _ := runCmd(10*time.Second, "whoami", "/groups")
	if strings.Contains(out, "S-1-16-12288") || strings.Contains(lower(out), "high mandatory level") {
		return []model.Finding{info("PRIV-ADMIN", "system", "Exécution avec privilèges élevés", "Couverture complète des contrôles.")}
	}
	return []model.Finding{info("PRIV-USER", "system", "Exécution sans privilèges administrateur",
		"Certains contrôles seront limités, dont BitLocker et une partie du registre. Relancer depuis un PowerShell élevé.")}
}

// registeredAV returns the third-party antivirus products registered with the
// Windows Security Center, excluding Defender itself. Windows automatically
// switches Defender to passive mode when another AV registers, so its
// real-time protection being off is expected, not a finding.
func registeredAV() []string {
	out, err := psCmd(`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName }`)
	if err != nil {
		return nil
	}
	var products []string
	for _, l := range strings.Split(out, "\n") {
		name := strings.TrimSpace(l)
		if name == "" || strings.Contains(lower(name), "windows defender") ||
			strings.Contains(lower(name), "microsoft defender") {
			continue
		}
		products = append(products, name)
	}
	return products
}

func winDefender(ctx *engine.Context) []model.Finding {
	thirdParty := registeredAV()

	out, err := psCmd(`$s=Get-MpComputerStatus; "$($s.RealTimeProtectionEnabled)|$($s.AntivirusEnabled)|$($s.AntivirusSignatureAge)"`)
	if err != nil || out == "" {
		if len(thirdParty) > 0 {
			return []model.Finding{info("AV-THIRDPARTY", "antivirus",
				"Protection assurée par un antivirus tiers",
				"Microsoft Defender n'a pas pu être interrogé, ce qui est normal lorsqu'un autre produit assure la protection en temps réel.",
				thirdParty...)}
		}
		return []model.Finding{info("AV-UNKNOWN", "antivirus",
			"Microsoft Defender n'a pas pu être interrogé",
			"La commande demande peut-être des privilèges élevés.")}
	}
	parts := strings.Split(out, "|")
	var findings []model.Finding

	rtpOff := len(parts) >= 1 && lower(strings.TrimSpace(parts[0])) == "false"
	switch {
	case rtpOff && len(thirdParty) > 0:
		findings = append(findings, info("AV-THIRDPARTY", "antivirus",
			"Defender est en veille, un antivirus tiers est actif",
			"Windows désactive la protection en temps réel de Defender dès qu'un autre antivirus s'enregistre auprès du centre de sécurité. Vérifier que le produit tiers est à jour et analyse réellement.",
			thirdParty...))
	case rtpOff:
		findings = append(findings, fail("AV-RTP", "antivirus",
			"Aucune protection antivirus en temps réel", model.SevHigh,
			"L'analyse en temps réel de Defender est désactivée et aucun antivirus tiers n'est enregistré auprès du centre de sécurité.",
			"Réactiver la protection dans Sécurité Windows, Protection contre les virus et menaces."))
	}

	if len(parts) >= 3 && !rtpOff {
		if age, ok := atoiSafe(strings.TrimSpace(parts[2])); ok && age > 7 {
			findings = append(findings, fail("AV-SIG", "antivirus",
				"Signatures de Defender périmées", model.SevMedium,
				fmt.Sprintf("Signatures vieilles de %d jours", age), "Mettre à jour les définitions."))
		}
	}
	if len(findings) == 0 {
		findings = append(findings, pass("AV-OK", "antivirus", "Protection en temps réel de Defender active"))
	}
	return findings
}

func winFirewall(ctx *engine.Context) []model.Finding {
	out, err := runCmd(10*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return []model.Finding{info("FW-UNKNOWN", "network", "État du pare-feu illisible", err.Error())}
	}
	var off []string
	profile := ""
	for _, l := range strings.Split(out, "\n") {
		ll := strings.TrimSpace(l)
		low := lower(ll)
		if strings.Contains(low, "profile settings") {
			profile = ll
		}
		if strings.HasPrefix(low, "state") && strings.Contains(low, "off") {
			off = append(off, profile)
		}
	}
	if len(off) > 0 {
		return []model.Finding{fail("FW-OFF", "network",
			"Pare-feu Windows désactivé sur un ou plusieurs profils", model.SevHigh,
			"Un pare-feu inactif expose tous les services en écoute.",
			"Réactiver le pare-feu sur chaque profil.", off...)}
	}
	return []model.Finding{pass("FW-ON", "network", "Pare-feu Windows actif sur tous les profils")}
}

func winUAC(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA")
	if err != nil {
		return []model.Finding{info("UAC-UNKNOWN", "hardening", "État du contrôle de compte d'utilisateur illisible", err.Error())}
	}
	if strings.Contains(out, "0x0") {
		return []model.Finding{fail("UAC-OFF", "hardening",
			"Contrôle de compte d'utilisateur (UAC) désactivé", model.SevHigh,
			"EnableLUA = 0", "Réactiver l'UAC. Désactivé, il laisse un programme malveillant s'élever sans un mot.")}
	}
	return []model.Finding{pass("UAC-ON", "hardening", "UAC actif")}
}

func winSMB1(ctx *engine.Context) []model.Finding {
	out, err := psCmd(`(Get-SmbServerConfiguration).EnableSMB1Protocol`)
	if err != nil || out == "" {
		return []model.Finding{info("SMB1-UNKNOWN", "hardening", "État de SMBv1 illisible", "")}
	}
	if lower(strings.TrimSpace(out)) == "true" {
		return []model.Finding{fail("SMB1-ON", "hardening",
			"SMBv1 est actif", model.SevHigh,
			"SMBv1 est obsolète et vulnérable, notamment à EternalBlue.",
			"Le désactiver avec Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.")}
	}
	return []model.Finding{pass("SMB1-OFF", "hardening", "SMBv1 désactivé")}
}

func winRDP(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	if err != nil {
		return []model.Finding{info("RDP-UNKNOWN", "network", "État du Bureau à distance illisible", "")}
	}
	if !strings.Contains(out, "0x0") {
		return []model.Finding{pass("RDP-OFF", "network", "Bureau à distance désactivé")}
	}
	// RDP enabled - check Network Level Authentication.
	nla, _ := runCmd(8*time.Second, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "/v", "UserAuthentication")
	if strings.Contains(nla, "0x0") {
		return []model.Finding{fail("RDP-NONLA", "network",
			"Bureau à distance actif sans authentification au niveau réseau", model.SevHigh,
			"Un Bureau à distance sans NLA est une porte d'entrée fréquente des rançongiciels.",
			"Activer la NLA, restreindre l'accès au VPN, imposer des mots de passe forts et un second facteur.")}
	}
	return []model.Finding{fail("RDP-ON", "network",
		"Bureau à distance actif", model.SevMedium,
		"Le Bureau à distance est joignable.",
		"Le restreindre par pare-feu aux réseaux de confiance, avec NLA et second facteur.")}
}

func winBitLocker(ctx *engine.Context) []model.Finding {
	out, err := runCmd(15*time.Second, "manage-bde", "-status", "C:")
	if err != nil || out == "" {
		return []model.Finding{info("BL-UNKNOWN", "disk",
			"État de BitLocker illisible", "Relancer avec des privilèges élevés pour vérifier le chiffrement du disque.")}
	}
	low := lower(out)
	if strings.Contains(low, "protection on") {
		return []model.Finding{pass("BL-ON", "disk", "BitLocker actif sur C:")}
	}
	return []model.Finding{fail("BL-OFF", "disk",
		"Disque système non chiffré par BitLocker", model.SevMedium,
		"Un disque non chiffré livre toutes les données en cas de perte ou de vol de la machine.",
		"Activer BitLocker sur C:.")}
}

func winPorts(ctx *engine.Context) []model.Finding {
	out, err := runCmd(15*time.Second, "netstat", "-ano", "-p", "tcp")
	if err != nil {
		return []model.Finding{info("NET-UNKNOWN", "network", "Ports en écoute illisibles", err.Error())}
	}
	risky := map[string]struct {
		sev   model.Severity
		label string
	}{
		"3389": {model.SevMedium, "RDP"},
		"445":  {model.SevMedium, "SMB"},
		"23":   {model.SevHigh, "telnet"},
		"21":   {model.SevMedium, "ftp"},
		"5985": {model.SevMedium, "WinRM (HTTP)"},
	}
	var inventory []string
	var findings []model.Finding
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, "LISTENING") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		local := f[1]
		colon := strings.LastIndex(local, ":")
		if colon < 0 {
			continue
		}
		addr, port := local[:colon], local[colon+1:]
		allIf := addr == "0.0.0.0" || addr == "[::]"
		scope := "locale"
		if allIf {
			scope = "toutes interfaces"
		}
		inventory = append(inventory, fmt.Sprintf("tcp/%s (%s)", port, scope))
		if r, ok := risky[port]; ok && allIf && !seen[port] {
			seen[port] = true
			findings = append(findings, fail("NET-PORT-TCP-"+port, "network",
				fmt.Sprintf("%s (port %s) exposé sur toutes les interfaces", r.label, port),
				r.sev, "Joignable depuis n'importe quel réseau.", "Restreindre par pare-feu ou désactiver le service."))
		}
	}
	sort.Strings(inventory)
	inventory = uniqueStrings(inventory)
	findings = append(findings, info("NET-LISTEN", "network",
		fmt.Sprintf("%d socket(s) TCP en écoute", len(inventory)),
		"Vérifier que chaque port ouvert est attendu.", capEvidence(inventory)...))
	return findings
}

// extractExePath pulls the executable path out of a `reg query` output line of
// the form:  NAME    REG_SZ    "C:\path\app.exe" --flags
func extractExePath(line string) string {
	idx := strings.Index(line, "REG_")
	if idx < 0 {
		return ""
	}
	rest := line[idx:]
	sp := strings.IndexAny(rest, " \t")
	if sp < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[sp:])
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, `"`) {
		if end := strings.Index(rest[1:], `"`); end >= 0 {
			return rest[1 : end+1]
		}
		return ""
	}
	low := lower(rest)
	for _, ext := range []string{".exe", ".dll"} {
		if i := strings.Index(low, ext); i >= 0 {
			return rest[:i+len(ext)]
		}
	}
	if s := strings.IndexAny(rest, " \t"); s >= 0 {
		return rest[:s]
	}
	return rest
}

// signedPaths returns the subset of the given files that carry a valid
// Authenticode signature. A signed binary from a real publisher living under
// AppData is a normal per-user install, not persistence.
func signedPaths(paths []string) map[string]bool {
	res := map[string]bool{}
	if len(paths) == 0 {
		return res
	}
	var quoted []string
	for _, p := range paths {
		quoted = append(quoted, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	script := "@(" + strings.Join(quoted, ",") + ") | ForEach-Object { " +
		"$s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; " +
		"if ($s -and $s.Status -eq 'Valid') { $_ } }"
	out, err := psCmd(script)
	if err != nil {
		return res
	}
	for _, l := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(l); p != "" {
			res[lower(p)] = true
		}
	}
	return res
}

func winStartup(ctx *engine.Context) []model.Finding {
	keys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	type candidate struct{ line, exe string }
	var candidates []candidate
	var inventory []string

	for _, k := range keys {
		out, err := runCmd(8*time.Second, "reg", "query", k)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(out, "\n") {
			ll := strings.TrimSpace(l)
			if ll == "" || strings.HasPrefix(ll, "HKEY") {
				continue
			}
			inventory = append(inventory, trunc(ll, 120))
			if containsAny(lower(ll), winSuspicious...) {
				candidates = append(candidates, candidate{line: trunc(ll, 120), exe: extractExePath(ll)})
			}
		}
	}

	// Only ask Windows about the files we actually need to judge.
	var toVerify []string
	for _, c := range candidates {
		if c.exe != "" {
			toVerify = append(toVerify, c.exe)
		}
	}
	signed := signedPaths(toVerify)

	var suspicious, vouched []string
	for _, c := range candidates {
		if c.exe != "" && signed[lower(c.exe)] {
			vouched = append(vouched, c.line)
			continue
		}
		suspicious = append(suspicious, c.line)
	}

	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("RUN-SUSP", "persistence",
			"Entrées de démarrage non signées dans un emplacement modifiable", model.SevHigh,
			"Ces entrées s'exécutent à l'ouverture de session depuis temp, AppData ou ProgramData, ou emploient des commandes encodées ou des binaires du système détournés, et ne portent aucune signature Authenticode valide.",
			"Vérifier chacune, retirer ce que vous n'avez pas installé.", capEvidence(suspicious)...))
	}
	if len(vouched) > 0 {
		out = append(out, info("RUN-SIGNED", "persistence",
			fmt.Sprintf("%d entrée(s) de démarrage signée(s) en emplacement modifiable", len(vouched)),
			"Installations par utilisateur provenant d'éditeurs identifiés. La signature étant valide, elles ne sont pas comptées comme persistance. À examiner tout de même si l'une vous est inconnue.",
			capEvidence(vouched)...))
	}
	out = append(out, info("RUN-INV", "persistence",
		fmt.Sprintf("%d entrée(s) de démarrage", len(inventory)),
		"Passer en revue l'inventaire de démarrage.", capEvidence(inventory)...))
	return out
}

func winTasks(ctx *engine.Context) []model.Finding {
	out, err := runCmd(30*time.Second, "schtasks", "/query", "/fo", "LIST", "/v")
	if err != nil || out == "" {
		return []model.Finding{info("TASK-UNKNOWN", "persistence", "Tâches planifiées non énumérables", "")}
	}
	var suspicious []string
	for _, l := range strings.Split(out, "\n") {
		ll := strings.TrimSpace(l)
		if !strings.HasPrefix(lower(ll), "task to run:") {
			continue
		}
		if containsAny(lower(ll), winSuspicious...) {
			suspicious = append(suspicious, trunc(ll, 140))
		}
	}
	if len(suspicious) > 0 {
		return []model.Finding{fail("TASK-SUSP", "persistence",
			"Action(s) de tâche planifiée suspecte(s)", model.SevHigh,
			"Les tâches planifiées sont un moyen de persistance courant et tenace.",
			"Inspecter chacune avec schtasks /query /tn <nom> /v.", capEvidence(suspicious)...)}
	}
	return []model.Finding{pass("TASK-OK", "persistence", "Aucune tâche planifiée manifestement suspecte")}
}

func winAdmins(ctx *engine.Context) []model.Finding {
	// The group is localised (Administrateurs, Administradores, ...) but its
	// SID never changes, so resolve by SID rather than by name.
	out, err := psCmd(`Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }`)
	if err != nil || strings.TrimSpace(out) == "" {
		// Fallback: resolve the localised name, then use net localgroup.
		name, nerr := psCmd(`(Get-LocalGroup -SID S-1-5-32-544).Name`)
		if nerr == nil && strings.TrimSpace(name) != "" {
			if raw, rerr := runCmd(10*time.Second, "net", "localgroup", strings.TrimSpace(name)); rerr == nil {
				out = parseNetLocalgroup(raw)
			}
		}
	}

	var members []string
	for _, l := range strings.Split(out, "\n") {
		if ll := strings.TrimSpace(l); ll != "" {
			members = append(members, ll)
		}
	}
	if len(members) == 0 {
		return []model.Finding{errFinding("ADM-UNKNOWN", "accounts",
			"Liste des administrateurs locaux indisponible",
			"Ni Get-LocalGroupMember ni net localgroup n'ont renvoyé de membres. Relancer avec des privilèges élevés.")}
	}
	return []model.Finding{info("ADM-LIST", "accounts",
		fmt.Sprintf("%d compte(s) administrateur local", len(members)),
		"Chaque compte administrateur est une cible de valeur. Garder cette liste au strict minimum.", members...)}
}

// parseNetLocalgroup extracts member names from `net localgroup <name>` output,
// which brackets the member list between a dashed rule and a trailing status line.
func parseNetLocalgroup(raw string) string {
	var members []string
	collect := false
	for _, l := range strings.Split(raw, "\n") {
		ll := strings.TrimSpace(l)
		if strings.HasPrefix(ll, "----") {
			collect = true
			continue
		}
		if strings.HasPrefix(lower(ll), "the command completed") ||
			strings.HasPrefix(lower(ll), "la commande s'est termin\u00e9e") {
			collect = false
		}
		if collect && ll != "" {
			members = append(members, ll)
		}
	}
	return strings.Join(members, "\n")
}

func atoiSafe(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
