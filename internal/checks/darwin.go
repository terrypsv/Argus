//go:build darwin

package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
)

func osChecks() []check {
	return []check{
		{Name: "privilege", Category: "system", Fn: macPrivilege},
		{Name: "sip", Category: "hardening", Fn: macSIP},
		{Name: "gatekeeper", Category: "hardening", Fn: macGatekeeper},
		{Name: "filevault", Category: "disk", Fn: macFileVault},
		{Name: "firewall", Category: "network", Fn: macFirewall},
		{Name: "disk-usage", Category: "disk", Fn: diskUsageCheck},
		{Name: "listening-ports", Category: "network", Fn: macPorts},
		{Name: "launch-agents", Category: "persistence", Fn: macLaunchAgents},
		{Name: "kernel-extensions", Category: "kernel", Fn: macKexts},
	}
}

// DefaultCriticalPaths are hashed by `argus baseline` on macOS.
func DefaultCriticalPaths() []string {
	return []string{
		"/bin/ls", "/bin/ps", "/bin/bash", "/bin/sh",
		"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/login",
		"/usr/bin/ssh", "/usr/sbin/sshd", "/usr/bin/curl",
		"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts",
	}
}

var macSuspicious = append([]string{"/users/shared/", "/tmp/", "~/library/"}, suspiciousCmdTokens...)

func macPrivilege(ctx *engine.Context) []model.Finding {
	if os.Geteuid() == 0 {
		return []model.Finding{info("PRIV-ROOT", "system", "Running as root", "Full coverage enabled.")}
	}
	return []model.Finding{info("PRIV-USER", "system", "Running without root",
		"Some checks may be limited. Re-run with sudo for full coverage.")}
}

func macSIP(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "csrutil", "status")
	if err != nil {
		return []model.Finding{info("SIP-UNKNOWN", "hardening", "Could not read SIP status", "")}
	}
	if strings.Contains(strings.ToLower(out), "enabled") {
		return []model.Finding{pass("SIP-ON", "hardening", "System Integrity Protection is enabled")}
	}
	return []model.Finding{fail("SIP-OFF", "hardening",
		"System Integrity Protection is disabled", model.SevHigh,
		out, "Re-enable SIP from Recovery mode (`csrutil enable`); disabled SIP lets malware modify the system.")}
}

func macGatekeeper(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "spctl", "--status")
	if err != nil {
		return []model.Finding{info("GK-UNKNOWN", "hardening", "Could not read Gatekeeper status", "")}
	}
	if strings.Contains(strings.ToLower(out), "assessments enabled") {
		return []model.Finding{pass("GK-ON", "hardening", "Gatekeeper is enabled")}
	}
	return []model.Finding{fail("GK-OFF", "hardening",
		"Gatekeeper is disabled", model.SevHigh,
		out, "Re-enable it (`sudo spctl --master-enable`) so unsigned apps are blocked.")}
}

func macFileVault(ctx *engine.Context) []model.Finding {
	out, err := runCmd(8*time.Second, "fdesetup", "status")
	if err != nil {
		return []model.Finding{info("FV-UNKNOWN", "disk", "Could not read FileVault status", "")}
	}
	if strings.Contains(strings.ToLower(out), "filevault is on") {
		return []model.Finding{pass("FV-ON", "disk", "FileVault disk encryption is on")}
	}
	return []model.Finding{fail("FV-OFF", "disk",
		"FileVault disk encryption is off", model.SevMedium,
		"Data on the disk is unencrypted at rest.", "Enable FileVault in System Settings > Privacy & Security.")}
}

func macFirewall(ctx *engine.Context) []model.Finding {
	const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if fileExists(sfw) {
		out, err := runCmd(8*time.Second, sfw, "--getglobalstate")
		if err == nil {
			if strings.Contains(strings.ToLower(out), "enabled") {
				return []model.Finding{pass("FW-ON", "network", "Application firewall is enabled")}
			}
			return []model.Finding{fail("FW-OFF", "network",
				"Application firewall is disabled", model.SevMedium,
				out, "Enable it in System Settings > Network > Firewall.")}
		}
	}
	// Fallback to the alf preference.
	out, err := runCmd(8*time.Second, "defaults", "read",
		"/Library/Preferences/com.apple.alf", "globalstate")
	if err != nil {
		return []model.Finding{info("FW-UNKNOWN", "network", "Could not read firewall state", "")}
	}
	if strings.TrimSpace(out) == "0" {
		return []model.Finding{fail("FW-OFF", "network",
			"Application firewall is disabled", model.SevMedium,
			"globalstate = 0", "Enable the firewall in System Settings.")}
	}
	return []model.Finding{pass("FW-ON", "network", "Application firewall is enabled")}
}

func macPorts(ctx *engine.Context) []model.Finding {
	var out string
	var err error
	if cmdAvailable("lsof") {
		out, err = runCmd(15*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	} else {
		out, err = runCmd(15*time.Second, "netstat", "-an", "-p", "tcp")
	}
	if err != nil && out == "" {
		return []model.Finding{info("NET-UNKNOWN", "network", "Could not read listening ports", "")}
	}

	risky := map[int]struct {
		sev   model.Severity
		label string
	}{
		23:   {model.SevHigh, "telnet"},
		21:   {model.SevMedium, "ftp"},
		5900: {model.SevMedium, "VNC/screen sharing"},
		445:  {model.SevMedium, "SMB"},
	}

	var inventory []string
	var findings []model.Finding
	seen := map[int]bool{}
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, "LISTEN") {
			continue
		}
		port, allIf, ok := parseListenAddr(l)
		if !ok {
			continue
		}
		scope := "local"
		if allIf {
			scope = "all interfaces"
		}
		inventory = append(inventory, fmt.Sprintf("tcp/%d (%s)", port, scope))
		if r, ok := risky[port]; ok && allIf && !seen[port] {
			seen[port] = true
			findings = append(findings, fail(fmt.Sprintf("NET-PORT-%d", port), "network",
				fmt.Sprintf("%s (port %d) exposed on all interfaces", r.label, port),
				r.sev, "Reachable from any network.", "Restrict via firewall or disable the service."))
		}
	}
	sort.Strings(inventory)
	dedup := uniqueStrings(inventory)
	findings = append(findings, info("NET-LISTEN", "network",
		fmt.Sprintf("%d listening TCP socket(s)", len(dedup)),
		"Confirm each open port is expected.", cap50(dedup)...))
	return findings
}

// parseListenAddr extracts a port and "all interfaces" flag from an lsof/netstat
// line by locating the host:port token.
func parseListenAddr(line string) (int, bool, bool) {
	for _, f := range strings.Fields(line) {
		colon := strings.LastIndex(f, ":")
		if colon < 0 {
			continue
		}
		host, portStr := f[:colon], f[colon+1:]
		portStr = strings.TrimSuffix(portStr, ".") // some netstat formats
		p, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		allIf := host == "*" || host == "0.0.0.0" || host == "[::]" || host == "::"
		return p, allIf, true
	}
	return 0, false, false
}

func macLaunchAgents(ctx *engine.Context) []model.Finding {
	dirs := []string{
		filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents"),
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
	}
	var suspicious, inventory []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			inventory = append(inventory, p)
			content := strings.ToLower(readFile(p))
			if containsAny(content, macSuspicious...) {
				suspicious = append(suspicious, p)
			}
		}
	}
	var out []model.Finding
	if len(suspicious) > 0 {
		out = append(out, fail("LA-SUSP", "persistence",
			"Suspicious LaunchAgent/Daemon(s)", model.SevHigh,
			"A launch item referencing temp dirs, shared folders or download/obfuscation tools is a common macOS persistence trick.",
			"Inspect each plist; remove anything you did not install.", cap50(suspicious)...))
	}
	out = append(out, info("LA-INV", "persistence",
		fmt.Sprintf("%d launch item(s)", len(inventory)),
		"Review the inventory of auto-launched items.", cap50(inventory)...))
	return out
}

func macKexts(ctx *engine.Context) []model.Finding {
	var out string
	var err error
	if cmdAvailable("kextstat") {
		out, err = runCmd(10*time.Second, "kextstat", "-l")
	} else {
		out, err = runCmd(10*time.Second, "kmutil", "showloaded")
	}
	if err != nil && out == "" {
		return []model.Finding{info("KEXT-UNKNOWN", "kernel", "Could not list kernel extensions", "")}
	}
	var thirdParty []string
	for _, l := range strings.Split(out, "\n") {
		low := strings.ToLower(l)
		if low == "" || strings.Contains(low, "com.apple") {
			continue
		}
		// Heuristic: lines that look like a loaded kext but are not Apple-signed.
		if strings.Contains(low, "com.") || strings.Contains(low, "org.") {
			thirdParty = append(thirdParty, trunc(strings.TrimSpace(l), 120))
		}
	}
	if len(thirdParty) > 0 {
		return []model.Finding{info("KEXT-3RD", "kernel",
			fmt.Sprintf("%d third-party kernel extension(s) loaded", len(thirdParty)),
			"Third-party kexts run in the kernel - verify each vendor is trusted.", cap50(thirdParty)...)}
	}
	return []model.Finding{pass("KEXT-OK", "kernel", "Only Apple kernel extensions loaded")}
}
