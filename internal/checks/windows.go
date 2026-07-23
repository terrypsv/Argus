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

func winDefender(ctx *engine.Context) []model.Finding {
	out, err := psCmd(`$s=Get-MpComputerStatus; "$($s.RealTimeProtectionEnabled)|$($s.AntivirusEnabled)|$($s.AntivirusSignatureAge)"`)
	if err != nil || out == "" {
		return []model.Finding{info("AV-UNKNOWN", "antivirus",
			"Could not query Microsoft Defender",
			"A third-party AV may be installed, or the command needs elevation.")}
	}
	parts := strings.Split(out, "|")
	var findings []model.Finding
	if len(parts) >= 1 && lower(strings.TrimSpace(parts[0])) == "false" {
		findings = append(findings, fail("AV-RTP", "antivirus",
			"Defender real-time protection is OFF", model.SevHigh,
			"Real-time scanning is disabled.", "Re-enable it (Windows Security > Virus & threat protection)."))
	}
	if len(parts) >= 3 {
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
	// RDP enabled — check Network Level Authentication.
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
			findings = append(findings, fail("NET-PORT-"+port, "network",
				fmt.Sprintf("%s (port %s) exposed on all interfaces", r.label, port),
				r.sev, "Reachable from any network.", "Restrict via firewall or disable the service."))
		}
	}
	sort.Strings(inventory)
	findings = append(findings, info("NET-LISTEN", "network",
		fmt.Sprintf("%d listening TCP socket(s)", len(inventory)),
		"Confirm each open port is expected.", cap50(inventory)...))
	return findings
}

func winStartup(ctx *engine.Context) []model.Finding {
	keys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	var suspicious, inventory []string
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
				suspicious = append(suspicious, trunc(ll, 120))
			}
		}
	}
	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("RUN-SUSP", "persistence",
			"Suspicious Run-key startup entry(ies)", model.SevHigh,
			"Autostart entries pointing at temp/AppData or using encoded commands are typical malware persistence.",
			"Verify each entry; remove anything you did not install.", cap50(suspicious)...))
	}
	out = append(out, info("RUN-INV", "persistence",
		fmt.Sprintf("%d autostart entry(ies)", len(inventory)),
		"Review the startup inventory.", cap50(inventory)...))
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
			"Inspect each with `schtasks /query /tn <name> /v`.", cap50(suspicious)...)}
	}
	return []model.Finding{pass("TASK-OK", "persistence", "No obviously suspicious scheduled tasks")}
}

func winAdmins(ctx *engine.Context) []model.Finding {
	out, err := runCmd(10*time.Second, "net", "localgroup", "administrators")
	if err != nil {
		return []model.Finding{info("ADM-UNKNOWN", "accounts", "Could not list local administrators", "")}
	}
	var members []string
	collect := false
	for _, l := range strings.Split(out, "\n") {
		ll := strings.TrimSpace(l)
		if strings.HasPrefix(ll, "----") {
			collect = true
			continue
		}
		if strings.HasPrefix(lower(ll), "the command completed") {
			collect = false
		}
		if collect && ll != "" {
			members = append(members, ll)
		}
	}
	return []model.Finding{info("ADM-LIST", "accounts",
		fmt.Sprintf("%d local administrator account(s)", len(members)),
		"Every admin account is a high-value target — keep this list minimal.", members...)}
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
