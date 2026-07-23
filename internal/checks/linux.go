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

	"argus/internal/engine"
	"argus/internal/model"
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
			"Running as root", "Full coverage enabled.")}
	}
	return []model.Finding{info("PRIV-USER", "system",
		"Running without root",
		"Some checks (shadow file, firewall rules, all cron spools) are limited. Re-run with sudo for full coverage.")}
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
		{"kernel.randomize_va_space", "Full ASLR", eqStr("2"), model.SevHigh,
			"Set kernel.randomize_va_space=2 in /etc/sysctl.d/."},
		{"kernel.kptr_restrict", "Kernel pointer hiding", geInt(1), model.SevMedium,
			"Set kernel.kptr_restrict=1 to hide kernel addresses from unprivileged users."},
		{"kernel.dmesg_restrict", "dmesg restriction", eqStr("1"), model.SevLow,
			"Set kernel.dmesg_restrict=1."},
		{"kernel.yama.ptrace_scope", "ptrace restriction", geInt(1), model.SevMedium,
			"Set kernel.yama.ptrace_scope=1 to block cross-process memory injection."},
		{"kernel.unprivileged_bpf_disabled", "Unprivileged eBPF disabled", eqStr("1"), model.SevMedium,
			"Set kernel.unprivileged_bpf_disabled=1."},
		{"fs.protected_hardlinks", "Hardlink protection", eqStr("1"), model.SevLow,
			"Set fs.protected_hardlinks=1."},
		{"fs.protected_symlinks", "Symlink protection", eqStr("1"), model.SevLow,
			"Set fs.protected_symlinks=1."},
		{"net.ipv4.conf.all.rp_filter", "Reverse-path filtering", geInt(1), model.SevLow,
			"Set net.ipv4.conf.all.rp_filter=1 to mitigate IP spoofing."},
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
			"kernel", r.label+" is weak/disabled", r.sev,
			fmt.Sprintf("%s = %q", r.key, v), r.fix))
	}
	if len(out) == 0 && okCount > 0 {
		out = append(out, pass("KRN-HARDENING", "kernel",
			fmt.Sprintf("Kernel hardening sysctls all set (%d checked)", okCount)))
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
		return []model.Finding{pass("KRN-TAINT", "kernel", "Kernel is not tainted")}
	}
	bits := map[int]string{
		1 << 0: "proprietary module loaded",
		1 << 4: "machine check",
		1 << 9: "kernel oops",
		1 << 11: "firmware workaround",
		1 << 12: "out-of-tree module loaded",
		1 << 13: "unsigned module loaded",
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
		"Kernel is tainted", sev,
		fmt.Sprintf("tainted=%d (%s)", n, strings.Join(flags, ", ")),
		"Out-of-tree or unsigned modules can hide malicious code; verify every non-distro module.",
		flags...)}
}

func ldPreloadCheck(ctx *engine.Context) []model.Finding {
	var out []model.Finding
	if fileExists("/etc/ld.so.preload") {
		out = append(out, fail("KRN-LDPRELOAD", "kernel",
			"/etc/ld.so.preload is present", model.SevHigh,
			"Global library preloading is a classic userland-rootkit hook.",
			"Confirm the listed libraries are legitimate; an unexpected entry means a likely rootkit.",
			readLines("/etc/ld.so.preload")...))
	}
	for _, l := range readLines("/etc/environment") {
		if strings.HasPrefix(strings.ToUpper(l), "LD_PRELOAD") {
			out = append(out, fail("KRN-ENVPRELOAD", "kernel",
				"LD_PRELOAD set globally in /etc/environment", model.SevHigh,
				l, "Remove unless you know exactly why it is there."))
		}
	}
	if len(out) == 0 {
		out = append(out, pass("KRN-LDPRELOAD", "kernel", "No global LD_PRELOAD hooks"))
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
			"Non-root account(s) with UID 0", model.SevCritical,
			"A UID-0 account has full root privileges — a textbook backdoor.",
			"Remove or fix the account immediately.", uid0...))
	} else {
		out = append(out, pass("ACC-UID0", "accounts", "Only root has UID 0"))
	}

	// Empty passwords in /etc/shadow (root only).
	shadow := readLines("/etc/shadow")
	if len(shadow) == 0 {
		out = append(out, info("ACC-SHADOW", "accounts",
			"Could not read /etc/shadow", "Re-run as root to check for empty passwords."))
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
				"Account(s) with an empty password", model.SevCritical,
				"These accounts can be used to log in with no password.",
				"Lock them (`passwd -l <user>`) or set a strong password.", empty...))
		} else {
			out = append(out, pass("ACC-EMPTYPW", "accounts", "No empty-password accounts"))
		}
	}
	return out
}

// --- ssh ----------------------------------------------------------------------

func sshHardeningCheck(ctx *engine.Context) []model.Finding {
	const cfg = "/etc/ssh/sshd_config"
	if !fileExists(cfg) {
		return []model.Finding{info("SSH-NONE", "ssh", "No sshd_config found", "OpenSSH server not installed.")}
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
	var out []model.Finding
	add := func(id, title string, sev model.Severity, detail, fix string) {
		out = append(out, fail(id, "ssh", title, sev, detail, fix))
	}
	if v := vals["permitrootlogin"]; v == "yes" {
		add("SSH-ROOT", "SSH permits root login with password", model.SevHigh,
			"PermitRootLogin yes", "Set `PermitRootLogin prohibit-password` or `no`.")
	}
	if v, ok := vals["passwordauthentication"]; !ok || v == "yes" {
		add("SSH-PWAUTH", "SSH password authentication enabled", model.SevMedium,
			"PasswordAuthentication is not disabled", "Prefer keys: set `PasswordAuthentication no`.")
	}
	if vals["permitemptypasswords"] == "yes" {
		add("SSH-EMPTYPW", "SSH permits empty passwords", model.SevCritical,
			"PermitEmptyPasswords yes", "Set `PermitEmptyPasswords no`.")
	}
	if vals["protocol"] == "1" {
		add("SSH-PROTO1", "SSH protocol 1 enabled", model.SevCritical,
			"Protocol 1", "Remove the Protocol directive (only v2 is safe).")
	}
	if vals["x11forwarding"] == "yes" {
		add("SSH-X11", "SSH X11 forwarding enabled", model.SevLow,
			"X11Forwarding yes", "Disable unless required.")
	}
	if len(out) == 0 {
		out = append(out, pass("SSH-OK", "ssh", "sshd_config passes hardening checks"))
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
		return []model.Finding{info("SUID-SKIP", "disk", "SUID scan skipped (quick mode)", "")}
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
			"SUID/SGID binary in a writable/temp location", model.SevHigh,
			"SUID binaries here are a common privilege-escalation backdoor.",
			"Investigate each; remove the SUID bit (`chmod -s`) if not required.",
			cap50(suspicious)...))
	}
	out = append(out, info("SUID-INV", "disk",
		fmt.Sprintf("%d SUID/SGID binaries found", len(all)),
		"Review the inventory and compare against a known-good host.",
		cap50(all)...))
	return out
}

func worldWritableCheck(ctx *engine.Context) []model.Finding {
	if ctx.Config.Quick {
		return []model.Finding{info("WW-SKIP", "disk", "World-writable scan skipped (quick mode)", "")}
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
			"World-writable file(s) in a system directory", model.SevHigh,
			"Any local user can modify these; a perfect persistence/tamper vector.",
			"Tighten permissions (`chmod o-w`).", cap50(wwSystem)...))
	}
	if len(wwDirNoSticky) > 0 {
		out = append(out, fail("WW-DIR", "disk",
			"World-writable directory without sticky bit", model.SevLow,
			"Users can delete/rename each other's files here.",
			"Add the sticky bit (`chmod +t`) or restrict write access.", cap50(wwDirNoSticky)...))
	}
	if len(out) == 0 {
		out = append(out, pass("WW-OK", "disk", "No dangerous world-writable entries found"))
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
			out = append(out, fail("MNT-"+strings.ToUpper(strings.Trim(target, "/")), "disk",
				target+" is not a separate mount", model.SevLow,
				"Cannot apply noexec/nosuid to "+target+".",
				"Consider a dedicated mount with noexec,nosuid,nodev."))
			continue
		}
		if !strings.Contains(found.opts, "noexec") {
			out = append(out, fail("MNT-NOEXEC-"+strings.ToUpper(strings.Trim(target, "/")), "disk",
				target+" is mounted without noexec", model.SevMedium,
				"opts: "+found.opts,
				"Remount "+target+" with noexec to block execution of dropped payloads."))
		}
	}
	if len(out) == 0 {
		out = append(out, pass("MNT-OK", "disk", "Temp filesystems mounted with safe flags"))
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
			"Suspicious cron entry(ies)", model.SevHigh,
			"Cron jobs downloading or executing from temp dirs are a common persistence mechanism.",
			"Review each line; remove anything you did not create.", cap50(suspicious)...))
	} else {
		out = append(out, pass("CRON-OK", "persistence",
			fmt.Sprintf("No suspicious cron entries (%d scanned)", total)))
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
			"Suspicious systemd service(s)", model.SevHigh,
			"A service whose ExecStart runs from a temp/writable path is a strong persistence indicator.",
			"Inspect the unit files and disable anything unexpected.", cap50(suspicious)...))
	} else {
		out = append(out, pass("SVC-OK", "persistence",
			fmt.Sprintf("No suspicious systemd services (%d scanned)", total)))
	}
	return out
}

// --- network ------------------------------------------------------------------

type listener struct {
	port    int
	allIf   bool
	proto   string
}

func parseProcTCP(path, proto string, v6 bool) []listener {
	var out []listener
	lines := readLines(path)
	for i, l := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(l)
		if len(f) < 4 || f[3] != "0A" { // 0A = TCP LISTEN
			continue
		}
		la := f[1]
		colon := strings.LastIndex(la, ":")
		if colon < 0 {
			continue
		}
		addrHex, portHex := la[:colon], la[colon+1:]
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		all := strings.Trim(addrHex, "0") == "" // 0.0.0.0 or ::
		out = append(out, listener{port: int(port), allIf: all, proto: proto})
	}
	return out
}

func portsCheck(ctx *engine.Context) []model.Finding {
	var ls []listener
	ls = append(ls, parseProcTCP("/proc/net/tcp", "tcp", false)...)
	ls = append(ls, parseProcTCP("/proc/net/tcp6", "tcp6", true)...)

	risky := map[int]struct {
		sev   model.Severity
		label string
	}{
		23: {model.SevHigh, "telnet (cleartext)"},
		21: {model.SevMedium, "ftp (cleartext)"},
		513: {model.SevMedium, "rlogin"},
		514: {model.SevMedium, "rsh"},
		6379: {model.SevHigh, "redis (often unauthenticated)"},
		27017: {model.SevHigh, "mongodb"},
		9200: {model.SevMedium, "elasticsearch"},
		3306: {model.SevMedium, "mysql exposed"},
		5432: {model.SevMedium, "postgres exposed"},
	}

	var out []model.Finding
	seen := map[int]bool{}
	var inventory []string
	for _, l := range ls {
		scope := "loopback/other"
		if l.allIf {
			scope = "all interfaces"
		}
		inventory = append(inventory, fmt.Sprintf("%s/%d (%s)", l.proto, l.port, scope))
		if r, ok := risky[l.port]; ok && l.allIf && !seen[l.port] {
			seen[l.port] = true
			out = append(out, fail(fmt.Sprintf("NET-PORT-%d", l.port), "network",
				fmt.Sprintf("Risky service on port %d exposed on all interfaces", l.port),
				r.sev, r.label, "Bind to localhost, add authentication, or firewall the port."))
		}
	}
	sort.Strings(inventory)
	out = append(out, info("NET-LISTEN", "network",
		fmt.Sprintf("%d listening TCP socket(s)", len(ls)),
		"Every open port is attack surface — confirm each is expected.", cap50(inventory)...))
	return out
}

func firewallCheck(ctx *engine.Context) []model.Finding {
	// ufw
	if cmdAvailable("ufw") {
		if out, err := runCmd(4*time.Second, "ufw", "status"); err == nil {
			if strings.Contains(strings.ToLower(out), "status: active") {
				return []model.Finding{pass("FW-UFW", "network", "ufw firewall is active")}
			}
		}
	}
	// nftables
	if cmdAvailable("nft") {
		if out, err := runCmd(4*time.Second, "nft", "list", "ruleset"); err == nil && strings.TrimSpace(out) != "" {
			if containsAny(out, "drop", "reject") {
				return []model.Finding{pass("FW-NFT", "network", "nftables ruleset present")}
			}
		}
	}
	// iptables
	if cmdAvailable("iptables") {
		if out, err := runCmd(4*time.Second, "iptables", "-S"); err == nil {
			if containsAny(out, "-j DROP", "-j REJECT") {
				return []model.Finding{pass("FW-IPT", "network", "iptables filtering rules present")}
			}
			return []model.Finding{fail("FW-NONE", "network",
				"No host firewall rules detected", model.SevMedium,
				"iptables shows only default-accept policies.",
				"Enable ufw/nftables or add iptables rules to limit inbound exposure.")}
		}
	}
	return []model.Finding{info("FW-UNKNOWN", "network",
		"Could not determine firewall state",
		"Re-run as root; no usable firewall tool responded.")}
}

// --- process / rootkit heuristics --------------------------------------------

func processCheck(ctx *engine.Context) []model.Finding {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []model.Finding{errFinding("PROC-READ", "process", "Cannot read /proc", err.Error())}
	}
	var deleted, tempExec []string
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
		if strings.HasSuffix(exe, " (deleted)") {
			deleted = append(deleted, e.Name()+" -> "+exe)
		}
		if containsAny(exe, suspiciousPathTokens...) {
			tempExec = append(tempExec, e.Name()+" -> "+exe)
		}
	}
	var out []model.Finding
	if len(deleted) > 0 {
		out = append(out, fail("PROC-DELETED", "process",
			"Process(es) running from a deleted binary", model.SevHigh,
			"Fileless malware often deletes its on-disk image while continuing to run.",
			"Inspect these PIDs (`ls -l /proc/<pid>/exe`, `cat /proc/<pid>/maps`) before killing.",
			cap50(deleted)...))
	}
	if len(tempExec) > 0 {
		out = append(out, fail("PROC-TEMPEXEC", "process",
			"Process(es) executing from a temp directory", model.SevHigh,
			"Legitimate services rarely run from /tmp or /dev/shm.",
			"Identify the parent and origin of each process.", cap50(tempExec)...))
	}
	if len(out) == 0 {
		out = append(out, pass("PROC-OK", "process", "No obvious process anomalies"))
	}
	return out
}


