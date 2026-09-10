package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// baseline is the on-disk integrity snapshot.
type baseline struct {
	CreatedAt time.Time         `json:"created_at"`
	Algorithm string            `json:"algorithm"`
	Files     map[string]string `json:"files"` // absolute path -> hex sha256
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteBaseline hashes each existing file in paths and stores the snapshot.
// Returns the number of files recorded.
func WriteBaseline(path string, paths []string) (int, error) {
	b := baseline{
		CreatedAt: time.Now(),
		Algorithm: "sha256",
		Files:     map[string]string{},
	}
	for _, p := range paths {
		if !fileExists(p) {
			continue
		}
		sum, err := hashFile(p)
		if err != nil {
			continue // unreadable (permissions) - skip rather than abort
		}
		b.Files[p] = sum
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, err
	}
	return len(b.Files), nil
}

// integrityCheck compares current hashes against the stored baseline.
func integrityCheck(ctx *engine.Context) []model.Finding {
	const cat = "integrity"
	path := ctx.Config.BaselinePath
	data, err := os.ReadFile(path)
	if err != nil {
		return []model.Finding{info("INTEG-NOBASE", cat,
			"Aucune référence d'intégrité enregistrée",
			fmt.Sprintf("Lancer d'abord argus baseline pour enregistrer les empreintes de confiance des fichiers critiques (cherché dans %s).", path))}
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return []model.Finding{errFinding("INTEG-BADBASE", cat,
			"Référence d'intégrité illisible", err.Error())}
	}

	var findings []model.Finding
	var changed, missing []string
	paths := make([]string, 0, len(b.Files))
	for p := range b.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		want := b.Files[p]
		if !fileExists(p) {
			missing = append(missing, p)
			continue
		}
		got, err := hashFile(p)
		if err != nil {
			continue
		}
		if got != want {
			changed = append(changed, p)
		}
	}

	if len(changed) > 0 {
		findings = append(findings, fail("INTEG-CHANGED", cat,
			fmt.Sprintf("%d fichier(s) critique(s) modifié(s) depuis la référence", len(changed)),
			model.SevHigh,
			"Un binaire ou une configuration surveillée diffère de la référence de confiance. C'est attendu après une mise à jour, mais c'est aussi le signe classique d'une altération ou d'un binaire piégé.",
			"Confirmer que le changement correspond à une mise à jour légitime, en comparant aux empreintes publiées par l'éditeur. Sinon, traiter la machine comme compromise.",
			changed...))
	}
	if len(missing) > 0 {
		findings = append(findings, fail("INTEG-MISSING", cat,
			fmt.Sprintf("%d fichier(s) de la référence introuvable(s)", len(missing)),
			model.SevMedium,
			"Des fichiers présents lors de la prise de référence ont disparu.",
			"Vérifier si la suppression était intentionnelle.",
			missing...))
	}
	if len(findings) == 0 {
		findings = append(findings, pass("INTEG-OK", cat,
			fmt.Sprintf("Les %d fichiers de la référence sont intacts", len(b.Files))))
	}
	return findings
}
