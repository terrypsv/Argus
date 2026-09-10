package checks

import (
	"strings"
	"testing"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// withVolumes replaces the system read for one test.
func withVolumes(t *testing.T, vols []volume) {
	t.Helper()
	previous := readVolumes
	readVolumes = func() []volume { return vols }
	t.Cleanup(func() { readVolumes = previous })
}

func findingByID(findings []model.Finding, prefix string) (model.Finding, bool) {
	for _, f := range findings {
		if strings.HasPrefix(f.ID, prefix) {
			return f, true
		}
	}
	return model.Finding{}, false
}

// Les deux seuils sont des decisions, pas des details d'implementation: les
// changer doit casser un test.
func TestDiskThresholds(t *testing.T) {
	cases := []struct {
		name     string
		pctUsed  int
		wantID   string
		wantSev  model.Severity
		wantNone bool
	}{
		{name: "sous le premier seuil", pctUsed: 89, wantNone: true},
		{name: "juste au seuil bas", pctUsed: 90, wantID: "DISK-LOW-", wantSev: model.SevLow},
		{name: "entre les deux", pctUsed: 97, wantID: "DISK-LOW-", wantSev: model.SevLow},
		{name: "juste au seuil haut", pctUsed: 98, wantID: "DISK-FULL-", wantSev: model.SevMedium},
		{name: "plein", pctUsed: 100, wantID: "DISK-FULL-", wantSev: model.SevMedium},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withVolumes(t, []volume{{name: "/", pctUsed: c.pctUsed}})
			findings := diskUsageCheck(&engine.Context{})

			alert, found := findingByID(findings, "DISK-FULL-")
			if !found {
				alert, found = findingByID(findings, "DISK-LOW-")
			}
			if c.wantNone {
				if found {
					t.Fatalf("%d%% a produit une alerte: %s", c.pctUsed, alert.ID)
				}
				return
			}
			if !found {
				t.Fatalf("%d%% n'a produit aucune alerte", c.pctUsed)
			}
			if !strings.HasPrefix(alert.ID, c.wantID) {
				t.Errorf("id = %q, want prefixe %q", alert.ID, c.wantID)
			}
			if alert.Severity != c.wantSev {
				t.Errorf("gravite = %v, want %v", alert.Severity, c.wantSev)
			}
		})
	}
}

// Un volume en lecture seule a 100% est normal par construction: macOS scelle
// "/" ainsi a chaque installation. Alerter dessus serait le faux positif le
// plus visible de l'outil.
func TestReadOnlyVolumeNeverAlerts(t *testing.T) {
	withVolumes(t, []volume{{name: "/", pctUsed: 100, readOnly: true}})
	findings := diskUsageCheck(&engine.Context{})

	for _, f := range findings {
		if strings.HasPrefix(f.ID, "DISK-FULL-") || strings.HasPrefix(f.ID, "DISK-LOW-") {
			t.Fatalf("un volume en lecture seule a produit %s", f.ID)
		}
	}

	inventory, found := findingByID(findings, "DISK-INV")
	if !found {
		t.Fatal("l'inventaire doit exister")
	}
	// Visible mais non alerte: retirer un volume de l'inventaire le rendrait
	// invisible, ce qui est un autre defaut.
	if !strings.Contains(strings.Join(inventory.Evidence, " "), "lecture seule") {
		t.Errorf("le volume doit rester dans l'inventaire, marque: %v", inventory.Evidence)
	}
}

// Aucune donnee n'est pas la meme chose qu'aucun probleme.
func TestNoVolumeDataIsReported(t *testing.T) {
	withVolumes(t, nil)
	findings := diskUsageCheck(&engine.Context{})

	if len(findings) != 1 {
		t.Fatalf("constats = %d, want 1", len(findings))
	}
	if findings[0].ID != "DISK-NONE" {
		t.Errorf("id = %q, want DISK-NONE", findings[0].ID)
	}
}

// Chaque volume est juge separement, et l'inventaire les compte tous.
func TestEachVolumeIsJudgedSeparately(t *testing.T) {
	withVolumes(t, []volume{
		{name: "/", pctUsed: 42},
		{name: "/var", pctUsed: 99},
		{name: "/boot", pctUsed: 91},
		{name: "/nix/store", pctUsed: 100, readOnly: true},
	})
	findings := diskUsageCheck(&engine.Context{})

	var full, low int
	for _, f := range findings {
		switch {
		case strings.HasPrefix(f.ID, "DISK-FULL-"):
			full++
		case strings.HasPrefix(f.ID, "DISK-LOW-"):
			low++
		}
	}
	if full != 1 || low != 1 {
		t.Errorf("plein = %d, bas = %d, want 1 et 1", full, low)
	}

	inventory, found := findingByID(findings, "DISK-INV")
	if !found {
		t.Fatal("inventaire absent")
	}
	if len(inventory.Evidence) != 4 {
		t.Errorf("inventaire = %d entrees, want 4", len(inventory.Evidence))
	}
	if !strings.Contains(inventory.Title, "4 volume") {
		t.Errorf("titre = %q", inventory.Title)
	}
}

// L'inventaire est trie: deux scans de la meme machine doivent se comparer
// ligne a ligne, ce qui est le sujet de la commande diff.
func TestInventoryIsSorted(t *testing.T) {
	withVolumes(t, []volume{
		{name: "/var", pctUsed: 10},
		{name: "/", pctUsed: 20},
		{name: "/boot", pctUsed: 30},
	})
	inventory, found := findingByID(diskUsageCheck(&engine.Context{}), "DISK-INV")
	if !found {
		t.Fatal("inventaire absent")
	}
	for i := 1; i < len(inventory.Evidence); i++ {
		if inventory.Evidence[i-1] > inventory.Evidence[i] {
			t.Fatalf("inventaire non trie: %v", inventory.Evidence)
		}
	}
}

// Un nom de volume entre dans l'identifiant du constat, qui doit rester
// stable et lisible d'un scan a l'autre.
func TestVolumeNameIsSanitisedIntoTheID(t *testing.T) {
	withVolumes(t, []volume{{name: "/Volumes/VMware Shared Folders", pctUsed: 99}})
	alert, found := findingByID(diskUsageCheck(&engine.Context{}), "DISK-FULL-")
	if !found {
		t.Fatal("aucune alerte")
	}
	for _, interdit := range []string{" ", "/", "\\", ":"} {
		if strings.Contains(alert.ID, interdit) {
			t.Errorf("identifiant contenant %q: %s", interdit, alert.ID)
		}
	}
}
