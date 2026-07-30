//go:build windows

package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
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
		return []model.Finding{info("PRIV-ADMIN", "system", "Running elevated", "Full coverage enabled.")}
	}
	return []model.Finding{info("PRIV-USER", "system", "Not running as Administrator",
		"Some checks (BitLocker, some registry hives) may be limited. Re-run in an elevated PowerShell.")}
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
				"Protection provided by a third-party antivirus",
				"Microsoft Defender could not be queried, which is normal when another product owns real-time protection.",
				thirdParty...)}
		}
		return []model.Finding{info("AV-UNKNOWN", "antivirus",
			"Could not query Microsoft Defender",
			"The command may need elevation.")}
	}
	parts := strings.Split(out, "|")
	var findings []model.Finding

	rtpOff := len(parts) >= 1 && lower(strings.TrimSpace(parts[0])) == "false"
	switch {
	case rtpOff && len(thirdParty) > 0:
		findings = append(findings, info("AV-THIRDPARTY", "antivirus",
			"Defender is passive; a third-party antivirus is active",
			"Windows disables Defender real-time protection when another antivirus registers with the Security Center. Verify the third-party product is up to date and actually scanning.",
			thirdParty...))
	case rtpOff:
		findings = append(findings, fail("AV-RTP", "antivirus",
			"No active real-time antivirus protection", model.SevHigh,
			"Defender real-time scanning is disabled and no third-party antivirus is registered with the Security Center.",
			"Re-enable it (Windows Security > Virus & threat protection)."))
	}

	if len(parts) >= 3 && !rtpOff {
		if age, ok := atoiSafe(strings.TrimSpace(parts[2])); ok && age > 7 {
			findings = append(findings, fail("AV-SIG", "antivirus",
				"Defender signatures are stale", model.SevMedium,
				fmt.Sprintf("Signature age: %d days", age), "Update definitions."))
		}
	}
	if len(findings) == 0 {
		findings = append(findings, pass("AV-OK", "antivirus", "Defender real-time protection is active"))
	}
	return findings
}

func winFirewall(ctx *engine.Context) []model.Finding {
	out, err := runCmd(10*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return []model.Finding{info("FW-UNKNOWN", "network", "Could not read firewall state", err.Error())}
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
			"Windows Firewall is OFF for one or more profiles", model.SevHigh,
			"An inactive firewall exposes all listening services.",
			"Turn the firewall on for every profile.", off...)}
	}
	return []model.Finding{pass("FW-ON", "network", "Windows Firewall is on for all profiles")}
}

func winUAC(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA")
	if err != nil {
		return []model.Finding{info("UAC-UNKNOWN", "hardening", "Could not read UAC state", err.Error())}
	}
	if strings.Contains(out, "0x0") {
		return []model.Finding{fail("UAC-OFF", "hardening",
			"User Account Control (UAC) is disabled", model.SevHigh,
			"EnableLUA = 0", "Re-enable UAC; disabled UAC lets malware elevate silently.")}
	}
	return []model.Finding{pass("UAC-ON", "hardening", "UAC is enabled")}
}

func winSMB1(ctx *engine.Context) []model.Finding {
	out, err := psCmd(`(Get-SmbServerConfiguration).EnableSMB1Protocol`)
	if err != nil || out == "" {
		return []model.Finding{info("SMB1-UNKNOWN", "hardening", "Could not query SMBv1 state", "")}
	}
	if lower(strings.TrimSpace(out)) == "true" {
		return []model.Finding{fail("SMB1-ON", "hardening",
			"SMBv1 is enabled", model.SevHigh,
			"SMBv1 is obsolete and vulnerable (e.g. EternalBlue).",
			"Disable it: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.")}
	}
	return []model.Finding{pass("SMB1-OFF", "hardening", "SMBv1 is disabled")}
}

func winRDP(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	if err != nil {
		return []model.Finding{info("RDP-UNKNOWN", "network", "Could not read RDP state", "")}
	}
	if !strings.Contains(out, "0x0") {
		return []model.Finding{pass("RDP-OFF", "network", "RDP is disabled")}
	}
	// RDP enabled - check Network Level Authentication.
	nla, _ := runCmd(8*time.Second, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "/v", "UserAuthentication")
	if strings.Contains(nla, "0x0") {
		return []model.Finding{fail("RDP-NONLA", "network",
			"RDP is enabled without Network Level Authentication", model.SevHigh,
			"RDP without NLA is a frequent ransomware entry point.",
			"Enable NLA, restrict RDP to VPN, and enforce strong passwords/MFA.")}
	}
	return []model.Finding{fail("RDP-ON", "network",
		"RDP is enabled", model.SevMedium,
		"Remote Desktop is reachable.",
		"Ensure it is firewalled to trusted networks only and NLA + MFA are enforced.")}
}

func winBitLocker(ctx *engine.Context) []model.Finding {
	out, err := runCmd(15*time.Second, "manage-bde", "-status", "C:")
	if err != nil || out == "" {
		return []model.Finding{info("BL-UNKNOWN", "disk",
			"Could not read BitLocker status", "Re-run elevated to check disk encryption.")}
	}
	low := lower(out)
	if strings.Contains(low, "protection on") {
		return []model.Finding{pass("BL-ON", "disk", "BitLocker protection is ON for C:")}
	}
	return []model.Finding{fail("BL-OFF", "disk",
		"System drive is not encrypted with BitLocker", model.SevMedium,
		"An unencrypted disk exposes all data if the device is lost or stolen.",
		"Enable BitLocker on C:.")}
}

func winPorts(ctx *engine.Context) []model.Finding {
	out, err := runCmd(15*time.Second, "netstat", "-ano", "-p", "tcp")
	if err != nil {
		return []model.Finding{info("NET-UNKNOWN", "network", "Could not read listening ports", err.Error())}
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
		scope := "local"
		if allIf {
			scope = "all interfaces"
		}
		inventory = append(inventory, fmt.Sprintf("tcp/%s (%s)", port, scope))
		if r, ok := risky[port]; ok && allIf && !seen[port] {
			seen[port] = true
			findings = append(findings, fail("NET-PORT-TCP-"+port, "network",
				fmt.Sprintf("%s (port %s) exposed on all interfaces", r.label, port),
				r.sev, "Reachable from any network.", "Restrict via firewall or disable the service."))
		}
	}
	sort.Strings(inventory)
	inventory = uniqueStrings(inventory)
	findings = append(findings, info("NET-LISTEN", "network",
		fmt.Sprintf("%d listening TCP socket(s)", len(inventory)),
		"Confirm each open port is expected.", capEvidence(inventory)...))
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
			"Unsigned autostart entry(ies) in a user-writable location", model.SevHigh,
			"These entries run at logon from temp/AppData/ProgramData, or use encoded or living-off-the-land commands, and carry no valid Authenticode signature.",
			"Verify each one; remove anything you did not install.", capEvidence(suspicious)...))
	}
	if len(vouched) > 0 {
		out = append(out, info("RUN-SIGNED", "persistence",
			fmt.Sprintf("%d signed autostart entry(ies) in user-writable paths", len(vouched)),
			"Per-user installs from real publishers. Signature valid, so not treated as persistence - review anyway if you do not recognise one.",
			capEvidence(vouched)...))
	}
	out = append(out, info("RUN-INV", "persistence",
		fmt.Sprintf("%d autostart entry(ies)", len(inventory)),
		"Review the startup inventory.", capEvidence(inventory)...))
	return out
}

func winTasks(ctx *engine.Context) []model.Finding {
	out, err := runCmd(30*time.Second, "schtasks", "/query", "/fo", "LIST", "/v")
	if err != nil || out == "" {
		return []model.Finding{info("TASK-UNKNOWN", "persistence", "Could not enumerate scheduled tasks", "")}
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
			"Suspicious scheduled task action(s)", model.SevHigh,
			"Scheduled tasks are a common, resilient persistence mechanism.",
			"Inspect each with `schtasks /query /tn <name> /v`.", capEvidence(suspicious)...)}
	}
	return []model.Finding{pass("TASK-OK", "persistence", "No obviously suspicious scheduled tasks")}
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
			"Could not list local administrators",
			"Neither Get-LocalGroupMember nor net localgroup returned members; re-run elevated.")}
	}
	return []model.Finding{info("ADM-LIST", "accounts",
		fmt.Sprintf("%d local administrator account(s)", len(members)),
		"Every admin account is a high-value target - keep this list minimal.", members...)}
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
			strings.HasPrefix(lower(ll), "la commande s'est terminée") {
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
