// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package checks

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"argus/internal/model"
)

func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestParseManifestV2HostsInPermissions(t *testing.T) {
	// Manifest v2 melange hotes et permissions dans la meme liste.
	body := `{"name":"Colour Picker","version":"1.2.0",
		"permissions":["<all_urls>","storage"]}`
	ext, ok := parseChromiumManifest("Chrome", "abc", "/tmp/x", []byte(body))
	if !ok {
		t.Fatal("manifeste v2 non lu")
	}
	if ext.Name != "Colour Picker" {
		t.Errorf("nom = %q", ext.Name)
	}
	if len(ext.Risky) == 0 {
		t.Error("<all_urls> devait etre signale")
	}
	if ext.Severity != model.SevHigh {
		t.Errorf("severite = %v, want haute", ext.Severity)
	}
}

// Manifest v3 separe les hotes: ne lire que "permissions" ferait manquer la
// moitie de l'exposition selon la version de l'extension.
func TestParseManifestV3HostPermissions(t *testing.T) {
	body := `{"name":"Reader","version":"3.0",
		"permissions":["storage"],
		"host_permissions":["https://*/*"]}`
	ext, _ := parseChromiumManifest("Chrome", "abc", "/tmp/x", []byte(body))
	if len(ext.Risky) == 0 {
		t.Error("host_permissions devait etre lu")
	}
}

// Un content script injecte donne l'acces a la page aussi surement qu'une
// permission d'hote.
func TestContentScriptMatchesCount(t *testing.T) {
	body := `{"name":"Injector","version":"1.0",
		"content_scripts":[{"matches":["*://*/*"]}]}`
	ext, _ := parseChromiumManifest("Chrome", "abc", "/tmp/x", []byte(body))
	if len(ext.Risky) == 0 {
		t.Error("un content script universel devait etre signale")
	}
}

func TestHarmlessExtensionIsNotFlagged(t *testing.T) {
	body := `{"name":"Theme","version":"1.0","permissions":["storage","alarms"]}`
	ext, _ := parseChromiumManifest("Chrome", "abc", "/tmp/x", []byte(body))
	if len(ext.Risky) != 0 {
		t.Errorf("extension inoffensive signalee: %v", ext.Risky)
	}
}

func TestBroadHostPatternVariants(t *testing.T) {
	broad := []string{"<all_urls>", "*://*/*", "https://*/*", "http://*/*", "file://*/*"}
	for _, p := range broad {
		if !isBroadHostPattern(p) && permissionRisk[p].meaning == "" {
			t.Errorf("motif universel non reconnu: %q", p)
		}
	}
	narrow := []string{"https://example.com/*", "*://mail.google.com/*"}
	for _, p := range narrow {
		if isBroadHostPattern(p) {
			t.Errorf("motif restreint pris pour universel: %q", p)
		}
	}
}

func TestMalformedManifestIsSkipped(t *testing.T) {
	if _, ok := parseChromiumManifest("Chrome", "abc", "/tmp/x", []byte("ceci n est pas du json")); ok {
		t.Error("un manifeste illisible ne doit pas produire d'extension")
	}
}

func TestNamelessExtensionFallsBackToID(t *testing.T) {
	ext, _ := parseChromiumManifest("Chrome", "identifiant", "/tmp/x", []byte(`{"version":"1"}`))
	if ext.Name != "identifiant" {
		t.Errorf("nom = %q, want l'identifiant", ext.Name)
	}
}

func TestReadChromiumExtensionsPicksLatestVersion(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "aaa", "1.0.0"), `{"name":"Vieux","version":"1.0.0"}`)
	writeManifest(t, filepath.Join(root, "aaa", "2.0.0"), `{"name":"Recent","version":"2.0.0"}`)

	found, ok := readChromiumExtensions("Chrome", root)
	if !ok {
		t.Fatal("repertoire non lu")
	}
	if len(found) != 1 {
		t.Fatalf("extensions = %d, want 1", len(found))
	}
	if found[0].Version != "2.0.0" {
		t.Errorf("version = %q, la plus recente devait etre retenue", found[0].Version)
	}
}

// Annoncer zero extension alors que le repertoire est illisible serait un
// faux tout-va-bien, ce que cette suite d'outils cherche a eviter.
func TestUnreadableDirectoryIsReportedNotSilenced(t *testing.T) {
	if _, ok := readChromiumExtensions("Chrome", "/repertoire/inexistant"); ok {
		t.Error("un repertoire illisible doit se signaler comme tel")
	}
}

func TestFirefoxXPIIsRead(t *testing.T) {
	root := t.TempDir()
	extDir := filepath.Join(root, "profil.default", "extensions")
	if err := os.MkdirAll(extDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	path := filepath.Join(extDir, "module@exemple.xpi")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	if _, err := w.Write([]byte(`{"name":"Module","version":"1.0","permissions":["<all_urls>"]}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = zw.Close()
	_ = f.Close()

	found, ok := readFirefoxExtensions(root)
	if !ok {
		t.Fatal("profil Firefox non lu")
	}
	if len(found) != 1 || found[0].Name != "Module" {
		t.Fatalf("extensions = %+v", found)
	}
	if len(found[0].Risky) == 0 {
		t.Error("les permissions du xpi devaient etre analysees")
	}
}

// Le defaut qui rendait le check aveugle: chercher un profil nomme "Default"
// alors que le navigateur cree "Profile 1" des qu un second compte existe.
// Un bulletin de sante propre obtenu en regardant au mauvais endroit est la
// pire forme d erreur.
func TestProfilesAreEnumeratedNotAssumed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// Arborescence Linux, la plus simple a poser dans un test.
	previous := runtimeGOOS
	runtimeGOOS = func() string { return "linux" }
	defer func() { runtimeGOOS = previous }()

	for _, profile := range []string{"Profile 1", "Profile 2"} {
		dir := filepath.Join(home, ".config", "google-chrome", profile, "Extensions")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}

	roots := extensionRoots()
	if len(roots) != 2 {
		t.Fatalf("profils trouves = %d, want 2: %+v", len(roots), roots)
	}
	for _, r := range roots {
		if !strings.Contains(r.browser, "Profile") {
			t.Errorf("le nom du profil doit rester visible: %q", r.browser)
		}
	}
}

func TestDefaultProfileKeepsPlainBrowserName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	previous := runtimeGOOS
	runtimeGOOS = func() string { return "linux" }
	defer func() { runtimeGOOS = previous }()

	dir := filepath.Join(home, ".config", "google-chrome", "Default", "Extensions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	roots := extensionRoots()
	if len(roots) != 1 || roots[0].browser != "Chrome" {
		t.Errorf("racines = %+v, want un seul Chrome sans suffixe", roots)
	}
}

func TestExtensionRootsCoverMajorBrowsers(t *testing.T) {
	// Le repertoire personnel du test ne contient rien: la liste doit etre
	// vide plutot que de pointer des chemins qui n'existent pas.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if got := extensionRoots(); len(got) != 0 {
		t.Errorf("racines = %v, want aucune sur un profil vide", got)
	}
}

func TestPermissionMeaningsAreExplained(t *testing.T) {
	// Une permission signalee sans explication oblige l'operateur a aller
	// chercher ailleurs ce qu'elle autorise.
	for perm, risk := range permissionRisk {
		if strings.TrimSpace(risk.meaning) == "" {
			t.Errorf("permission %q signalee sans explication", perm)
		}
	}
}
