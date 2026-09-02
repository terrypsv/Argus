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
			"Could not enumerate local accounts",
			"dscl returned nothing usable. No claim is made about privileged accounts."))
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
				"Could not parse the account list",
				"dscl output did not contain any name/uid pair in the expected shape."))
		case len(uid0) > 0:
			out = append(out, fail("ACC-UID0", "accounts",
				fmt.Sprintf("%d account(s) other than root hold UID 0", len(uid0)),
				model.SevCritical,
				"A second UID 0 account is full root access under another name, and is a classic way to keep privileged access after a compromise.",
				"Remove the account or give it a normal UID.", capEvidence(uid0)...))
		default:
			out = append(out, pass("ACC-UID0", "accounts", "Only root holds UID 0"))
		}
	}

	// --- administrators ------------------------------------------------------
	if admins, aErr := runCmd(15*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); aErr == nil {
		if i := strings.Index(admins, ":"); i >= 0 {
			members := strings.Fields(admins[i+1:])
			if len(members) > 0 {
				out = append(out, info("ADM-LIST", "accounts",
					fmt.Sprintf("%d administrator account(s)", len(members)),
					"Every one of these can escalate to root. Confirm each is expected.",
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
				"Guest account is enabled", model.SevMedium,
				"Anyone with physical access gets a session without credentials.",
				"Disable it in System Settings > Users & Groups."))
		case "0":
			out = append(out, pass("GUEST-OFF", "accounts", "Guest account is disabled"))
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
			"Could not read the Remote Login setting",
			"systemsetup failed, usually for lack of privilege or Full Disk Access. Nothing is claimed about SSH exposure."))
	case strings.Contains(login, "On"):
		sshOn = true
		out = append(out, fail("SSH-REMOTE", "ssh",
			"Remote Login (SSH) is enabled", model.SevMedium,
			"The host accepts SSH sessions from the network.",
			"Turn it off in System Settings > General > Sharing if you do not need it."))
	case strings.Contains(login, "Off"):
		out = append(out, pass("SSH-REMOTE", "ssh", "Remote Login (SSH) is disabled"))
	default:
		out = append(out, errFinding("SSH-REMOTE", "ssh",
			"Unrecognised Remote Login output",
			"systemsetup answered in a shape this check does not understand, so no conclusion is drawn."))
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
				"Screen Sharing is enabled", model.SevMedium,
				"The desktop is reachable over VNC, a protocol whose macOS implementation authenticates but does not protect the session end to end.",
				"Disable it in System Settings > General > Sharing if unused."))
		}
	}
	if on, why := ardActive(); on {
		out = append(out, fail("RM-ON", "network",
			"Remote Management (ARD) is enabled", model.SevMedium,
			"Apple Remote Desktop allows screen control and remote command execution. Detected by "+why+".",
			"Disable it in System Settings > General > Sharing if unused."))
	}

	// Access granted to every local account is a much broader grant than access
	// granted to named users, so it is reported separately and more severely.
	if allUsers, aErr := runCmd(10*time.Second, "defaults", "read",
		"/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers"); aErr == nil {
		if strings.TrimSpace(allUsers) == "1" {
			out = append(out, fail("ARD-ALLUSERS", "network",
				"Remote Management is open to all local users", model.SevHigh,
				"Every local account, including any added later, gets screen control and remote command execution.",
				"Restrict Remote Management to named users."))
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
			return true, "the ARD activation trigger"
		}
	}
	if out, err := runCmd(10*time.Second, "pgrep", "-x", "ARDAgent"); err == nil && strings.TrimSpace(out) != "" {
		return true, "a running ARDAgent process"
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
		return []model.Finding{info("SSH-NOCONF", "ssh", "No sshd_config found",
			"Remote Login is on but the configuration file is missing; the daemon is running on built-in defaults.")}
	}
	lines := readLines(path)
	if len(lines) == 0 {
		return []model.Finding{errFinding("SSH-NOCONF", "ssh",
			"sshd_config could not be read",
			"Remote Login is enabled but its configuration was unreadable, so no claim is made about it.")}
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
			"SSH permits root login", model.SevHigh,
			"PermitRootLogin yes lets an attacker attack root directly, with no audit trail of who escalated.",
			"Set PermitRootLogin no, or prohibit-password at the very least."))
	}
	if v := value("PasswordAuthentication"); v == "yes" {
		out = append(out, fail("SSH-PWAUTH", "ssh",
			"SSH password authentication is enabled", model.SevMedium,
			"Passwords can be guessed at scale; keys cannot.",
			"Set PasswordAuthentication no once key-based login works."))
	}
	if v := value("PermitEmptyPasswords"); v == "yes" {
		out = append(out, fail("SSH-EMPTYPW", "ssh",
			"SSH permits empty passwords", model.SevCritical,
			"Any account with no password becomes a remote entry point.",
			"Set PermitEmptyPasswords no."))
	}
	if len(out) == 0 {
		out = append(out, pass("SSH-CONF", "ssh", "sshd configuration has no obvious weakness"))
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
			"Could not read the signed system volume status",
			"csrutil returned nothing usable, so no claim is made."))
	case strings.Contains(low, "disabled"):
		out = append(out, fail("SSV-OFF", "hardening",
			"Signed system volume is disabled", model.SevHigh,
			"The seal that makes system binaries immutable has been removed, which is a deliberate act and a prerequisite for persistent system-level tampering.",
			"Re-enable it from Recovery: csrutil authenticated-root enable."))
	case strings.Contains(low, "enabled"):
		out = append(out, pass("SSV-ON", "hardening", "Signed system volume is enabled"))
	default:
		out = append(out, errFinding("SSV-STATE", "hardening",
			"Unrecognised signed system volume output",
			"csrutil answered in a shape this check does not understand."))
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
			"Automatic update checks are disabled", model.SevMedium,
			"The machine will not learn that a patch exists.",
			"Re-enable update checks in System Settings > General > Software Update."))
	}
	if v, ok := readFlag("CriticalUpdateInstall"); ok && v == "0" {
		out = append(out, fail("UPD-NOCRITICAL", "hardening",
			"Automatic install of critical security updates is disabled", model.SevMedium,
			"XProtect and malware-removal definitions will not update on their own.",
			"Enable security responses in System Settings > General > Software Update."))
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
			"Could not list system extensions",
			"systemextensionsctl returned nothing usable, so no claim is made about loaded extensions.")}
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
		return []model.Finding{pass("SYSEXT-NONE", "kernel", "No third-party system extensions are active")}
	}
	return []model.Finding{info("SYSEXT-ACTIVE", "kernel",
		fmt.Sprintf("%d active system extension(s)", len(active)),
		"System extensions run with high privilege and can inspect network traffic or filter files. Confirm each vendor is expected.",
		capEvidence(active)...)}
}
