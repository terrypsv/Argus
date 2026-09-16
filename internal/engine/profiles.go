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
		Summary: "Machine polyvalente. Tous les contrôles s'appliquent.",
		Waivers: map[string]string{},
	},
	"audit": {
		Name:    "audit",
		Summary: "Station de test d'intrusion ou d'analyse de logiciels malveillants.",
		Waivers: map[string]string{
			"KRN-KERNEL-YAMA-PTRACE_SCOPE": "les débogueurs et les outils d'injection exigent un ptrace sans restriction",
			"KRN-KERNEL-KPTR_RESTRICT":     "les adresses du noyau sont nécessaires au développement d'exploits",
			"KRN-KERNEL-DMESG_RESTRICT":    "la lecture du journal du noyau fait partie du travail",
			"MNT-NOEXEC-TMP":               "l'outillage exécute couramment des charges depuis /tmp",
			"MNT-NOEXEC-DEV-SHM":           "l'outillage exécute couramment des charges depuis /dev/shm",
		},
	},
	"container": {
		Name:    "container",
		Summary: "Charge conteneurisée. Le noyau et les montages relèvent de l'hôte.",
		Waivers: map[string]string{
			"KRN-KERNEL-YAMA-PTRACE_SCOPE":    "les sysctls sont hérités de l'hôte et ne peuvent pas être posés ici",
			"KRN-KERNEL-KPTR_RESTRICT":        "les sysctls sont hérités de l'hôte et ne peuvent pas être posés ici",
			"KRN-KERNEL-DMESG_RESTRICT":       "les sysctls sont hérités de l'hôte et ne peuvent pas être posés ici",
			"KRN-NET-IPV4-CONF-ALL-RP_FILTER": "les sysctls réseau relèvent de l'espace de noms de l'hôte",
			"MNT-NOEXEC-TMP":                  "les options de montage sont décidées par le moteur de conteneurs",
			"MNT-NOEXEC-DEV-SHM":              "les options de montage sont décidées par le moteur de conteneurs",
			"MNT-VAR-TMP":                     "la disposition des montages est décidée par l'image, pas par la charge",
			"FW-NONE":                         "le filtrage relève de l'hôte ou de l'orchestrateur",
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
		return Profile{}, fmt.Errorf("profil inconnu %q (disponibles: %s)",
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
			Reason:     fmt.Sprintf("profil %q: %s", p.Name, why),
			AcceptedBy: "profile",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
