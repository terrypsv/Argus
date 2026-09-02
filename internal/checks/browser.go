// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package checks

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// Browser extensions are the widest hole in a workstation's posture, and the
// one nobody audits.
//
// An extension runs inside the browser, after TLS has been terminated and
// after the user has authenticated. An extension holding host permissions on
// every site can read the bank page, the webmail, the internal application and
// the session cookies that go with them. No firewall, no antivirus and no
// network monitoring sees any of it, because from the outside it is the
// browser doing what browsers do.
//
// The gap between what an extension claims to be and what it may do is where
// the risk lives. A colour-picker asking for access to all sites is not
// necessarily malicious, but it is one silent update away from being so, and
// the permission was granted years ago by someone who no longer works here.
//
// This check reads the manifests actually on disk rather than querying an
// extension store. A store lists what an extension declares today; the
// manifest is what the browser will enforce at the next page load.

// permissionRisk grades what a permission actually allows.
//
// The grading answers "what could this extension do if it turned hostile
// tomorrow", not "is this extension malicious". That distinction matters: an
// honest extension with excessive permissions is a real exposure, because the
// permission survives a change of ownership, and extension ownership changes
// hands quietly.
var permissionRisk = map[string]struct {
	severity model.Severity
	meaning  string
}{
	"<all_urls>":      {model.SevHigh, "lit et modifie le contenu de tous les sites visites"},
	"*://*/*":         {model.SevHigh, "lit et modifie le contenu de tous les sites visites"},
	"http://*/*":      {model.SevHigh, "lit et modifie le contenu de tous les sites en clair"},
	"https://*/*":     {model.SevHigh, "lit et modifie le contenu de tous les sites chiffres"},
	"cookies":         {model.SevHigh, "lit les cookies, donc les sessions ouvertes"},
	"webRequest":      {model.SevHigh, "observe toutes les requetes reseau du navigateur"},
	"debugger":        {model.SevHigh, "pilote le navigateur comme le ferait un outil de developpement"},
	"nativeMessaging": {model.SevHigh, "communique avec un programme installe hors du navigateur"},
	"proxy":           {model.SevHigh, "redirige le trafic du navigateur"},
	"history":         {model.SevMedium, "lit l'historique de navigation complet"},
	"downloads":       {model.SevMedium, "declenche et lit les telechargements"},
	"management":      {model.SevMedium, "active ou desactive les autres extensions"},
	"tabs":            {model.SevMedium, "voit les adresses de tous les onglets ouverts"},
	"clipboardRead":   {model.SevMedium, "lit le presse-papiers"},
	"bookmarks":       {model.SevLow, "lit et modifie les favoris"},
	"geolocation":     {model.SevLow, "lit la position"},
}

type extension struct {
	Browser  string
	ID       string
	Name     string
	Version  string
	Path     string
	Perms    []string
	Risky    []string
	Severity model.Severity
	Enabled  bool
}

// chromiumManifest is the subset of manifest.json that decides exposure.
type chromiumManifest struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Permissions     []any    `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	OptionalPerms   []any    `json:"optional_permissions"`
	ContentScripts  []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
}

func browserExtensionsCheck(ctx *engine.Context) []model.Finding {
	roots := extensionRoots()
	if len(roots) == 0 {
		return []model.Finding{info("EXT-NONE", "browser",
			"Aucun profil de navigateur trouve",
			"Aucun repertoire d'extensions connu n'existe sur ce poste.")}
	}

	var all []extension
	scanned := 0
	for _, root := range roots {
		found, ok := readExtensions(root.browser, root.path)
		if !ok {
			continue
		}
		scanned++
		all = append(all, found...)
	}

	if scanned == 0 {
		// Announcing zero extensions when the directories could not be read
		// would be a false all-clear, which is worse than saying nothing.
		return []model.Finding{errFinding("EXT-READ", "browser",
			"Les repertoires d'extensions n'ont pas pu etre lus",
			"Les profils existent mais leur contenu est inaccessible. Relancer avec les droits de l'utilisateur concerne.")}
	}

	if len(all) == 0 {
		return []model.Finding{pass("EXT-CLEAN", "browser",
			"Aucune extension de navigateur installee")}
	}

	var out []model.Finding
	sort.Slice(all, func(i, j int) bool {
		if all[i].Severity != all[j].Severity {
			return all[i].Severity > all[j].Severity
		}
		return all[i].Name < all[j].Name
	})

	var risky, inventory []string
	worst := model.SevLow
	for _, ext := range all {
		line := fmt.Sprintf("%s: %s %s (%s)", ext.Browser, ext.Name, ext.Version, ext.ID)
		inventory = append(inventory, line)
		if len(ext.Risky) == 0 {
			continue
		}
		risky = append(risky, line+" -> "+strings.Join(ext.Risky, "; "))
		if ext.Severity > worst {
			worst = ext.Severity
		}
	}

	// The inventory is a finding in its own right. Most workstations have
	// extensions nobody remembers installing, and listing them is half the
	// value of the check.
	out = append(out, info("EXT-INVENTORY", "browser",
		fmt.Sprintf("%d extension(s) de navigateur installee(s)", len(all)),
		"Une extension s'execute apres le dechiffrement TLS et apres l'authentification. Ni le pare-feu ni la supervision reseau ne voient ce qu'elle lit.",
		inventory...))

	if len(risky) > 0 {
		out = append(out, fail("EXT-PERMISSIONS", "browser",
			fmt.Sprintf("%d extension(s) disposent de permissions etendues", len(risky)),
			worst,
			"Ces extensions peuvent lire ou modifier le contenu des pages visitees, y compris les sessions authentifiees. Le risque ne tient pas a leur honnetete actuelle: une permission accordee survit a un changement de proprietaire, et les extensions changent de mains discretement.",
			"Verifier que chaque extension listee est encore utilisee et que ses permissions correspondent a sa fonction reelle. Retirer celles qui ne servent plus. Une extension de mise en forme n'a aucune raison de lire tous les sites.",
			risky...))
	} else {
		out = append(out, pass("EXT-PERMISSIONS", "browser",
			"Aucune extension ne dispose de permissions etendues"))
	}

	return out
}

type extensionRoot struct {
	browser string
	path    string
}

// extensionRoots lists the profile directories worth reading on this machine.
//
// Profiles are enumerated rather than assumed. The obvious implementation
// looks for a directory named "Default", which is what a fresh install
// creates; but the moment a second account is added the profiles become
// "Profile 1", "Profile 2", and the browser may never create "Default" at all.
// A check that hardcodes the name then reports zero extensions on a machine
// full of them, which is the worst kind of wrong: a clean bill of health
// produced by looking in the wrong place.
//
// Only the current user's profiles are inspected. Reading another account's
// browser data would need privileges the check does not require and should not
// want: a posture tool that rummages through other users' sessions is itself a
// liability.
func extensionRoots() []extensionRoot {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var out []extensionRoot

	// Chromium layout: <user data>/<profile>/Extensions, one directory per
	// profile whatever it is called.
	addChromium := func(browser string, parts ...string) {
		base := filepath.Join(append([]string{home}, parts...)...)
		entries, err := os.ReadDir(base)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			candidate := filepath.Join(base, entry.Name(), "Extensions")
			st, err := os.Stat(candidate)
			if err != nil || !st.IsDir() {
				continue
			}
			label := browser
			// The profile name is kept when there is more than one, because
			// "an extension on Edge" and "an extension on the work profile of
			// Edge" are different pieces of information.
			if entry.Name() != "Default" {
				label = browser + " / " + entry.Name()
			}
			out = append(out, extensionRoot{browser: label, path: candidate})
		}
	}

	// Some builds keep a single profile with the Extensions directory at the
	// root rather than under a profile name; Opera does this.
	addDirect := func(browser string, parts ...string) {
		path := filepath.Join(append([]string{home}, parts...)...)
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			out = append(out, extensionRoot{browser: browser, path: path})
		}
	}

	addFirefox := func(parts ...string) {
		path := filepath.Join(append([]string{home}, parts...)...)
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			out = append(out, extensionRoot{browser: "Firefox", path: path})
		}
	}

	switch runtimeGOOS() {
	case "windows":
		local := []string{"AppData", "Local"}
		addChromium("Chrome", append(local, "Google", "Chrome", "User Data")...)
		addChromium("Edge", append(local, "Microsoft", "Edge", "User Data")...)
		addChromium("Brave", append(local, "BraveSoftware", "Brave-Browser", "User Data")...)
		addChromium("Vivaldi", append(local, "Vivaldi", "User Data")...)
		addDirect("Opera", "AppData", "Roaming", "Opera Software", "Opera Stable", "Extensions")
		addFirefox("AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	case "darwin":
		support := []string{"Library", "Application Support"}
		addChromium("Chrome", append(support, "Google", "Chrome")...)
		addChromium("Edge", append(support, "Microsoft Edge")...)
		addChromium("Brave", append(support, "BraveSoftware", "Brave-Browser")...)
		addChromium("Vivaldi", append(support, "Vivaldi")...)
		addFirefox("Library", "Application Support", "Firefox", "Profiles")
	default:
		addChromium("Chrome", ".config", "google-chrome")
		addChromium("Chromium", ".config", "chromium")
		addChromium("Edge", ".config", "microsoft-edge")
		addChromium("Brave", ".config", "BraveSoftware", "Brave-Browser")
		addChromium("Vivaldi", ".config", "vivaldi")
		addFirefox(".mozilla", "firefox")
	}
	return out
}

// readExtensions walks one profile directory. The second return value says
// whether the directory could be read at all, which is not the same as finding
// nothing in it.
func readExtensions(browser, root string) ([]extension, bool) {
	if strings.HasPrefix(browser, "Firefox") {
		return readFirefoxExtensions(root)
	}
	return readChromiumExtensions(browser, root)
}

// readChromiumExtensions reads the Chromium layout: one directory per
// extension id, one directory per installed version inside it.
func readChromiumExtensions(browser, root string) ([]extension, bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, false
	}

	var out []extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		versions, err := os.ReadDir(filepath.Join(root, id))
		if err != nil {
			continue
		}
		// Several versions can remain on disk after an update. The last one in
		// alphabetical order is the closest thing to "current" available
		// without parsing the browser's own state database.
		var latest string
		for _, v := range versions {
			if v.IsDir() && v.Name() > latest {
				latest = v.Name()
			}
		}
		if latest == "" {
			continue
		}
		manifestPath := filepath.Join(root, id, latest, "manifest.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		ext, ok := parseChromiumManifest(browser, id, manifestPath, data)
		if ok {
			out = append(out, ext)
		}
	}
	return out, true
}

// readFirefoxExtensions reads the Firefox layout: profiles, each holding
// packed .xpi archives whose manifest is inside the archive.
func readFirefoxExtensions(root string) ([]extension, bool) {
	profiles, err := os.ReadDir(root)
	if err != nil {
		return nil, false
	}

	var out []extension
	read := false
	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}
		dir := filepath.Join(root, profile.Name(), "extensions")
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		read = true
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".xpi") {
				continue
			}
			path := filepath.Join(dir, f.Name())
			data, err := manifestFromXPI(path)
			if err != nil {
				continue
			}
			id := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
			if ext, ok := parseChromiumManifest("Firefox", id, path, data); ok {
				out = append(out, ext)
			}
		}
	}
	return out, read
}

// manifestFromXPI pulls manifest.json out of a packed extension.
func manifestFromXPI(path string) ([]byte, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	for _, f := range reader.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		// Bounded read: a crafted archive should not be able to exhaust memory
		// through a manifest claiming to be a gigabyte long.
		return io.ReadAll(io.LimitReader(rc, 1<<20))
	}
	return nil, fmt.Errorf("manifest.json absent de %s", path)
}

func parseChromiumManifest(browser, id, path string, data []byte) (extension, bool) {
	var m chromiumManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return extension{}, false
	}

	ext := extension{
		Browser: browser,
		ID:      id,
		Name:    strings.TrimSpace(m.Name),
		Version: m.Version,
		Path:    path,
	}
	if ext.Name == "" {
		ext.Name = id
	}

	// Manifest v2 lists hosts among the permissions; v3 separates them into
	// host_permissions. Both have to be read, or half the exposure is missed
	// depending on which version the extension was built against.
	claimed := map[string]bool{}
	collect := func(values []any) {
		for _, v := range values {
			if s, ok := v.(string); ok {
				claimed[s] = true
			}
		}
	}
	collect(m.Permissions)
	collect(m.OptionalPerms)
	for _, h := range m.HostPermissions {
		claimed[h] = true
	}
	// Content scripts declare the pages they are injected into, which grants
	// page access just as effectively as a host permission.
	for _, cs := range m.ContentScripts {
		for _, match := range cs.Matches {
			claimed[match] = true
		}
	}

	worst := model.SevLow
	for perm := range claimed {
		ext.Perms = append(ext.Perms, perm)
		risk, known := permissionRisk[perm]
		if !known {
			// A host pattern that is not in the table but covers everything is
			// still total access; matching on the shape catches the variants.
			if isBroadHostPattern(perm) {
				risk = struct {
					severity model.Severity
					meaning  string
				}{model.SevHigh, "lit et modifie le contenu de tous les sites visites"}
				known = true
			}
		}
		if !known {
			continue
		}
		ext.Risky = append(ext.Risky, perm+" ("+risk.meaning+")")
		if risk.severity > worst {
			worst = risk.severity
		}
	}
	sort.Strings(ext.Perms)
	sort.Strings(ext.Risky)
	ext.Severity = worst
	return ext, true
}

// isBroadHostPattern reports whether a match pattern covers every site.
func isBroadHostPattern(pattern string) bool {
	if pattern == "<all_urls>" {
		return true
	}
	// A pattern granting every host under any scheme ends in "://*/" plus a
	// wildcard path, which is total access however it is spelled.
	return strings.Contains(pattern, "://*/") && strings.HasSuffix(pattern, "*")
}
