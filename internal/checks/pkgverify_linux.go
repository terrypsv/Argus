//go:build linux

package checks

import (
	"fmt"
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
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
			"Package verification not run",
			"Re-run with --verify-packages to compare every installed file against the digests published by your distribution. It takes several minutes but, unlike a local baseline, it cannot have been poisoned before the first scan.")}
	}

	var raw string
	var manager string
	switch {
	case cmdAvailable("dpkg"):
		manager = "dpkg"
		// Discrepancies make dpkg exit non-zero, so the output matters more
		// than the status.
		raw, _ = runCmd(20*time.Minute, "dpkg", "--verify")
	case cmdAvailable("rpm"):
		manager = "rpm"
		raw, _ = runCmd(20*time.Minute, "rpm", "-Va")
	default:
		return []model.Finding{info("PKG-NONE", "integrity",
			"No supported package manager found",
			"Neither dpkg nor rpm is available; falling back to the local baseline only.")}
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
		state := "modified"
		if a.missing {
			state = "missing"
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
			fmt.Sprintf("%d packaged file(s) no longer match the vendor digest", len(altered)),
			model.SevHigh,
			"These files were installed by a package but their contents differ from what the distribution published. Documentation and configuration are excluded, so this should not happen on an untouched system.",
			"Compare against a clean copy (`apt-get install --reinstall <pkg>` or `rpm -V <pkg>`) and investigate before reinstalling - reinstalling destroys the evidence.",
			cap50(altered)...))
	}
	if len(missing) > 0 {
		out = append(out, fail("PKG-MISSING", "integrity",
			fmt.Sprintf("%d packaged file(s) are missing", len(missing)),
			model.SevLow,
			"Files the package manager expects are absent, outside documentation and configuration. Usually a stripped image, occasionally a binary removed to hide a tool.",
			"Confirm the removals were intentional.", cap50(missing)...))
	}
	if len(configs) > 0 {
		out = append(out, info("PKG-CONFIG", "integrity",
			fmt.Sprintf("%d configuration file(s) changed since installation", len(configs)),
			"Expected: configuration files exist to be edited. Listed so an unexpected one stands out.",
			cap50(configs)...))
	}
	if len(docs) > 0 {
		out = append(out, info("PKG-DOC", "integrity",
			fmt.Sprintf("%d documentation file(s) changed since installation", len(docs)),
			"Manuals, changelogs and locales hold nothing executable. Compressed docs in particular differ whenever a package is rebuilt, which is why they never raise an alert.",
			cap50(docs)...))
	}
	if len(altered) == 0 && len(missing) == 0 {
		out = append(out, pass("PKG-OK", "integrity",
			fmt.Sprintf("Every packaged binary matches the digest published by the distribution (%s)", manager)))
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
