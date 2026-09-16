//go:build linux

package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// Package verification compares every installed file against the digests
// published by the distribution.
//
// This matters because a locally generated baseline suffers from trust on first
// use: if the host was already compromised when `argus baseline` ran, the
// tampered binary was recorded as legitimate and will match forever. The
// package manager's digests were produced by the distribution before this
// machine existed, so they cannot have been poisoned locally.
//
// The trade-off is cost: verification re-hashes every packaged file and takes
// minutes on a full install. It is therefore opt-in rather than silently slow.

// pkgAnomaly is one file the package manager reports as altered.
type pkgAnomaly struct {
	path    string
	flags   string
	config  bool
	doc     bool
	missing bool
}

func pkgVerifyCheck(ctx *engine.Context) []model.Finding {
	if !ctx.Config.VerifyPackages {
		return []model.Finding{info("PKG-SKIPPED", "integrity",
			"Vérification par le gestionnaire de paquets non effectuée",
			"Relancez avec --verify-packages pour comparer chaque fichier installé aux empreintes publiées par votre distribution. Cela prend plusieurs minutes, mais contrairement à une référence prise localement, ces empreintes ne peuvent pas avoir été faussées avant la première analyse.")}
	}

	var raw string
	var warn string
	var manager string
	switch {
	case cmdAvailable("dpkg"):
		manager = "dpkg"
		// Discrepancies make dpkg exit non-zero, so the output matters more
		// than the status.
		raw, warn, _ = runCmdSeparate(20*time.Minute, "dpkg", "--verify")
	case cmdAvailable("rpm"):
		manager = "rpm"
		raw, warn, _ = runCmdSeparate(20*time.Minute, "rpm", "-Va")
	default:
		return []model.Finding{info("PKG-NONE", "integrity",
			"Aucun gestionnaire de paquets reconnu",
			"Ni dpkg ni rpm n'est disponible: seule la référence locale peut servir de comparaison.")}
	}

	var altered, missing, configs, docs []string
	for _, l := range strings.Split(raw, "\n") {
		a, ok := parseVerifyLine(l)
		if !ok {
			continue
		}
		if !a.missing && !contentAltered(a.flags) {
			// Size, mtime, ownership and permission drift happen for benign
			// reasons. Only a digest mismatch proves the contents changed.
			continue
		}
		state := "modifié"
		if a.missing {
			state = "disparu"
		}
		switch {
		case a.doc:
			docs = append(docs, a.path+"  ("+state+")")
		case a.config:
			configs = append(configs, a.path+"  ("+state+")")
		case a.missing:
			missing = append(missing, a.path)
		default:
			altered = append(altered, fmt.Sprintf("%s  %s", a.flags, a.path))
		}
	}

	var out []model.Finding
	if len(altered) > 0 {
		out = append(out, fail("PKG-ALTERED", "integrity",
			fmt.Sprintf("%d fichier(s) empaqueté(s) ne correspondent plus à l'empreinte de l'éditeur", len(altered)),
			model.SevHigh,
			"Ces fichiers ont été installés par un paquet, mais leur contenu diffère de ce que la distribution a publié. La documentation et la configuration sont écartées: cela ne devrait donc pas arriver sur un système intact.",
			"Comparer à une copie saine (apt-get install --reinstall <paquet>, ou rpm -V <paquet>) et enquêter avant de réinstaller: réinstaller détruit la preuve.",
			capEvidence(altered)...))
	}
	if len(missing) > 0 {
		out = append(out, fail("PKG-MISSING", "integrity",
			fmt.Sprintf("%d fichier(s) empaqueté(s) ont disparu", len(missing)),
			model.SevLow,
			"Des fichiers que le gestionnaire de paquets attend sont absents, hors documentation et configuration. C'est souvent une image allégée, parfois un binaire retiré pour dissimuler un outil.",
			"Confirmer que ces suppressions étaient volontaires.", capEvidence(missing)...))
	}
	if len(configs) > 0 {
		out = append(out, info("PKG-CONFIG", "integrity",
			fmt.Sprintf("%d fichier(s) de configuration modifiés depuis l'installation", len(configs)),
			"Attendu: un fichier de configuration existe pour être modifié. Ils sont listés pour qu'un fichier inattendu se remarque.",
			capEvidence(configs)...))
	}
	if len(docs) > 0 {
		out = append(out, info("PKG-DOC", "integrity",
			fmt.Sprintf("%d fichier(s) de documentation modifiés depuis l'installation", len(docs)),
			"Manuels, journaux de version et traductions ne contiennent rien d'exécutable. Les documents compressés en particulier diffèrent dès qu'un paquet est reconstruit, ce qui explique qu'ils ne lèvent jamais d'alerte.",
			capEvidence(docs)...))
	}
	// Ce que le gestionnaire n'a pas pu comparer doit se voir. Sans cela, une
	// vérification partielle rend le même verdict qu'une vérification complète.
	if warn != "" {
		out = append(out, info("PKG-WARN", "integrity",
			"Le gestionnaire de paquets a signalé des difficultés",
			"Ces messages viennent de "+manager+" pendant la comparaison. Ce qu'il n'a pas pu lire n'apparaît nulle part ailleurs dans ce rapport.",
			capEvidence(lignesNonVides(warn))...))
	}
	// La réussite n'est déclarée que si rien ne manque et que rien n'a résisté
	// à la comparaison.
	if len(altered) == 0 && len(missing) == 0 && warn == "" {
		out = append(out, pass("PKG-OK", "integrity",
			fmt.Sprintf("Tous les binaires empaquetés correspondent aux empreintes publiées par la distribution (%s)", manager)))
	}
	return out
}

// docPrefixes hold nothing executable. A compressed changelog changes digest
// whenever a package is rebuilt, which is noise, not tampering.
var docPrefixes = []string{
	"/usr/share/doc/", "/usr/share/man/", "/usr/share/info/",
	"/usr/share/locale/", "/usr/share/help/", "/usr/share/licenses/",
}

// parseVerifyLine handles both `dpkg --verify` and `rpm -Va`, whose output
// shares the same shape: a flag string, an optional attribute marker, and an
// absolute path.
func parseVerifyLine(line string) (pkgAnomaly, bool) {
	fields := strings.Fields(strings.TrimRight(line, "\r"))
	if len(fields) < 2 {
		return pkgAnomaly{}, false
	}
	a := pkgAnomaly{
		flags: fields[0],
		path:  fields[len(fields)-1],
	}
	if !strings.HasPrefix(a.path, "/") {
		return pkgAnomaly{}, false
	}
	// rpm places an attribute marker between the flags and the path
	// (c = config, d = documentation). dpkg does not always emit one, so the
	// path is the reliable signal and the marker only reinforces it.
	if len(fields) >= 3 {
		switch fields[len(fields)-2] {
		case "c":
			a.config = true
		case "d", "r", "l":
			a.doc = true
		}
	}
	if strings.HasPrefix(a.path, "/etc/") {
		a.config = true
	}
	if hasAnyPrefix(a.path, docPrefixes...) {
		a.doc = true
	}
	if strings.EqualFold(a.flags, "missing") {
		a.missing = true
	}
	return a, true
}

// contentAltered reports whether the digest differs. It is the only flag that
// proves the file's contents changed; the others drift for benign reasons.
func contentAltered(flags string) bool {
	return strings.Contains(flags, "5")
}

// lignesNonVides découpe un texte en lignes utiles, sans les vides.
func lignesNonVides(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
