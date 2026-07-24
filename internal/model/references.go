package model

import "strings"

// Framework names a published security standard.
type Framework string

const (
	// FrameworkMITRE identifies adversary techniques. It answers "what is the
	// attacker doing?", which is what a SOC needs to correlate a finding with
	// its detections.
	FrameworkMITRE Framework = "MITRE ATT&CK"
	// FrameworkANSSI is the French national agency's GNU/Linux hardening guide.
	FrameworkANSSI Framework = "ANSSI-BP-028"
	// FrameworkCIS is the Center for Internet Security benchmark series.
	FrameworkCIS Framework = "CIS Benchmark"
)

// Reference ties a finding to a control in a published standard.
//
// A finding without a reference is an opinion. A finding with one is an
// auditable control that someone else can verify, contest, or carry into a
// compliance file — which is the difference between a script and a tool a
// security officer can act on.
type Reference struct {
	Framework Framework `json:"framework"`
	ID        string    `json:"id"`
	Title     string    `json:"title"`
}

func (r Reference) String() string { return string(r.Framework) + " " + r.ID }

// mitre is a shorthand for building an ATT&CK reference.
func mitre(id, title string) Reference {
	return Reference{Framework: FrameworkMITRE, ID: id, Title: title}
}

// exactReferences maps a full finding ID to the controls it implements.
//
// RULE: an entry is added only once verified against the published document.
// A wrong reference in an audit tool is worse than a missing one, because it
// traces a decision back to a text that does not say that. Unverified mappings
// belong in the issue tracker, not here.
var exactReferences = map[string][]Reference{
	// --- Persistence ---------------------------------------------------------
	"RUN-SUSP":   {mitre("T1547.001", "Registry Run Keys / Startup Folder")},
	"RUN-SIGNED": {mitre("T1547.001", "Registry Run Keys / Startup Folder")},
	"RUN-INV":    {mitre("T1547.001", "Registry Run Keys / Startup Folder")},
	"TASK-SUSP":  {mitre("T1053.005", "Scheduled Task")},
	"TASK-OK":    {mitre("T1053.005", "Scheduled Task")},
	"CRON-SUSP":  {mitre("T1053.003", "Cron")},
	"CRON-OK":    {mitre("T1053.003", "Cron")},
	"SVC-SUSP":   {mitre("T1543.002", "Systemd Service")},
	"SVC-OK":     {mitre("T1543.002", "Systemd Service")},
	"LA-SUSP": {
		mitre("T1543.001", "Launch Agent"),
		mitre("T1543.004", "Launch Daemon"),
	},
	"LA-INV": {
		mitre("T1543.001", "Launch Agent"),
		mitre("T1543.004", "Launch Daemon"),
	},
	"KEXT-3RD": {mitre("T1547.006", "Kernel Modules and Extensions")},

	// --- Tampering and execution --------------------------------------------
	"PROC-MEMFD":    {mitre("T1620", "Reflective Code Loading")},
	"KRN-TAINT":     {mitre("T1014", "Rootkit")},
	"KRN-LDPRELOAD": {mitre("T1574.006", "Dynamic Linker Hijacking")},
	"KRN-ENVPRELOAD": {
		mitre("T1574.006", "Dynamic Linker Hijacking"),
	},
	"INTEG-CHANGED": {mitre("T1554", "Compromise Host Software Binary")},
	"PKG-ALTERED":   {mitre("T1554", "Compromise Host Software Binary")},
	"PKG-MISSING":   {mitre("T1070.004", "File Deletion")},
	"SUID-SUSP":     {mitre("T1548.001", "Setuid and Setgid")},
	"SUID-INV":      {mitre("T1548.001", "Setuid and Setgid")},
	"WW-SYSTEM":     {mitre("T1222", "File and Directory Permissions Modification")},
	"WW-DIR":        {mitre("T1222", "File and Directory Permissions Modification")},

	// --- Accounts and remote access -----------------------------------------
	"ACC-UID0":  {mitre("T1078.003", "Local Accounts")},
	"ADM-LIST":  {mitre("T1078.003", "Local Accounts")},
	"RDP-ON":    {mitre("T1021.001", "Remote Desktop Protocol")},
	"RDP-NONLA": {mitre("T1021.001", "Remote Desktop Protocol")},
	"SSH-PWAUTH": {
		mitre("T1021.004", "SSH"),
	},

	// --- Defences -----------------------------------------------------------
	"AV-RTP":  {mitre("T1562.001", "Disable or Modify Tools")},
	"FW-NONE": {mitre("T1562.004", "Disable or Modify System Firewall")},
	"FW-OFF":  {mitre("T1562.004", "Disable or Modify System Firewall")},

	// --- Hardening, verified against the published guide ---------------------
	// ANSSI-BP-028 v2.0, R25: load the Yama LSM at boot and set
	// kernel.yama.ptrace_scope to at least 1.
	"KRN-KERNEL-YAMA-PTRACE_SCOPE": {
		{Framework: FrameworkANSSI, ID: "R25", Title: "Configuration sysctl du module Yama"},
	},
}

// ReferencesFor returns the published controls a finding maps to, or nil when
// none has been verified yet. Callers must treat nil as "not yet mapped", never
// as "no standard covers this".
func ReferencesFor(id string) []Reference {
	if refs, ok := exactReferences[strings.ToUpper(strings.TrimSpace(id))]; ok {
		return refs
	}
	return nil
}

// CoverageStats reports how many known finding IDs carry a reference. It exists
// so the gap stays measurable instead of being quietly forgotten.
func CoverageStats() (mapped int, frameworks []Framework) {
	seen := map[Framework]bool{}
	for _, refs := range exactReferences {
		mapped++
		for _, r := range refs {
			if !seen[r.Framework] {
				seen[r.Framework] = true
				frameworks = append(frameworks, r.Framework)
			}
		}
	}
	return mapped, frameworks
}
