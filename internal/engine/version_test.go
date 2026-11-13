// Copyright (c) 2026 Terry PASSAVE. Tous droits réservés.

package engine

import "testing"

func TestVersionResolue(t *testing.T) {
	cas := []struct {
		nom, tamponnee, module, attendue string
	}{
		{"la publication prime", "v1.3.0", "v1.3.1-0.20261111093000-1e21e54a1375", "v1.3.0"},
		{"étiquette lue dans Git", "dev", "v1.3.0", "v1.3.0"},
		{"commit hors étiquette", "dev", "v1.3.1-0.20261111093000-1e21e54a1375+dirty", "v1.3.1-0.20261111093000-1e21e54a1375+dirty"},
		{"go run sans version", "dev", "(devel)", "dev"},
		{"aucune information", "dev", "", "dev"},
		{"tampon vide", "", "v1.2.0", "v1.2.0"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if obtenue := versionResolue(c.tamponnee, c.module); obtenue != c.attendue {
				t.Fatalf("versionResolue(%q, %q) = %q, attendu %q", c.tamponnee, c.module, obtenue, c.attendue)
			}
		})
	}
}
