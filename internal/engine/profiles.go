package engine

import (
	"fmt"
	"sort"
	"strings"
)

// A profile encodes what a class of machine is *for*.
//
// A hardening control that a machine deliberately does not satisfy is not a
// failure, it is a design decision: a pentest workstation needs ptrace to
// debug, a container cannot set kernel sysctls at all. Scoring those as faults
// produces a permanently red result, and a permanently red result is one nobody
// reads.
//
// Profiles are deliberately expressed as ordinary exceptions rather than as a
// second scoring path. That means a profiled waiver behaves exactly like a
// human one: it stays visible in the report, it carries its justification, and
// the raw score still shows what the machine would score without it. A profile
// can soften the headline number; it can never hide anything.
type Profile struct {
	Name    string
	Summary string
	// Waivers maps a finding ID to the reason this class of machine is allowed
	// not to satisfy it.
	Waivers map[string]string
}

var profiles = map[string]Profile{
	"workstation": {
		Name:    "workstation",
		Summary: "General-purpose machine. Every control applies.",
		Waivers: map[string]string{},
	},
	"audit": {
		Name:    "audit",
		Summary: "Penetration-testing or malware-analysis workstation.",
		Waivers: map[string]string{
			"KRN-KERNEL-YAMA-PTRACE_SCOPE": "debuggers and injection tooling require unrestricted ptrace",
			"KRN-KERNEL-KPTR_RESTRICT":     "kernel addresses are needed for exploit development",
			"KRN-KERNEL-DMESG_RESTRICT":    "kernel log access is part of the workflow",
			"MNT-NOEXEC-TMP":               "tooling routinely executes payloads from /tmp",
			"MNT-NOEXEC-DEV-SHM":           "tooling routinely executes payloads from /dev/shm",
		},
	},
	"container": {
		Name:    "container",
		Summary: "Containerised workload. Kernel and mount settings belong to the host.",
		Waivers: map[string]string{
			"KRN-KERNEL-YAMA-PTRACE_SCOPE":    "sysctls are inherited from the host and cannot be set here",
			"KRN-KERNEL-KPTR_RESTRICT":        "sysctls are inherited from the host and cannot be set here",
			"KRN-KERNEL-DMESG_RESTRICT":       "sysctls are inherited from the host and cannot be set here",
			"KRN-NET-IPV4-CONF-ALL-RP_FILTER": "network sysctls belong to the host namespace",
			"MNT-NOEXEC-TMP":                  "mount options are decided by the container runtime",
			"MNT-NOEXEC-DEV-SHM":              "mount options are decided by the container runtime",
			"MNT-VAR-TMP":                     "mount layout is decided by the image, not the workload",
			"FW-NONE":                         "filtering is the host's or the orchestrator's responsibility",
		},
	},
}

// ProfileNames lists the available profiles, sorted.
func ProfileNames() []string {
	var names []string
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LookupProfile resolves a profile by name.
func LookupProfile(name string) (Profile, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return profiles["workstation"], nil
	}
	p, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (available: %s)",
			name, strings.Join(ProfileNames(), ", "))
	}
	return p, nil
}

// exceptions converts the profile's waivers into ordinary exceptions. They
// never expire: a profile describes what the machine is, not a temporary
// decision someone should revisit in ninety days.
func (p Profile) exceptions() []Exception {
	var out []Exception
	for id, why := range p.Waivers {
		out = append(out, Exception{
			ID:         id,
			Reason:     fmt.Sprintf("profile %q: %s", p.Name, why),
			AcceptedBy: "profile",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
