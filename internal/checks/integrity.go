package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
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

// classifyChanged sépare les fichiers modifiés selon leur signature.
//
// Un fichier système modifié ne dit rien par lui-même: une mise à jour et un
// remplacement produisent la même empreinte différente. La signature tranche,
// parce qu'un éditeur signe ce qu'il livre et qu'un attaquant ne peut pas
// produire cette signature sans sa clé privée.
//
// Le cas où la vérification n'a pas pu tourner est traité à part, et c'est
// délibéré: conclure "non signé" sur une panne d'outillage lèverait une alerte
// critique sur un fichier sain, et un outil qui crie au loup pour cette raison
// cesse d'être lu.
func classifyChanged(changed []string) []model.Finding {
	const cat = "integrity"

	nonVerifiable := func() []model.Finding {
		return []model.Finding{fail("INTEG-CHANGED", cat,
			fmt.Sprintf("%d fichier(s) critique(s) modifié(s) depuis la référence", len(changed)),
			model.SevHigh,
			"Un binaire ou une configuration surveillée diffère de la référence de confiance, et la signature de ces fichiers n'a pas pu être vérifiée. C'est attendu après une mise à jour, mais c'est aussi le signe classique d'une altération.",
			"Comparer aux empreintes publiées par l'éditeur avant de conclure. Sur une distribution Linux, argus scan --verify-packages compare chaque fichier installé aux empreintes de la distribution.",
			changed...)}
	}

	if !canVerifySignatures() {
		return nonVerifiable()
	}
	signed, ok := verifySignatures(changed)
	if !ok {
		return nonVerifiable()
	}

	var tampered, updated []string
	for _, p := range changed {
		if authority, isSigned := signed[strings.ToLower(p)]; isSigned {
			updated = append(updated, p+"  ["+authority+"]")
			continue
		}
		tampered = append(tampered, p)
	}

	var out []model.Finding
	if len(tampered) > 0 {
		out = append(out, fail("INTEG-TAMPERED", cat,
			fmt.Sprintf("%d fichier(s) critique(s) modifié(s) et non signé(s)", len(tampered)),
			model.SevCritical,
			"Ces fichiers diffèrent de la référence et ne portent aucune signature valide. Un éditeur signe ce qu'il livre: un binaire système modifié sans signature n'a pas été remplacé par une mise à jour.",
			"Traiter la machine comme compromise. Ne pas reprendre la référence avant d'avoir établi d'où vient le remplacement.",
			capEvidence(tampered)...))
	}
	if len(updated) > 0 {
		out = append(out, fail("INTEG-UPDATED", cat,
			fmt.Sprintf("%d fichier(s) critique(s) modifié(s) par une mise à jour signée", len(updated)),
			model.SevMedium,
			"Ces fichiers diffèrent de la référence mais portent une signature d'éditeur valide, ce qui correspond à une mise à jour. La référence est donc périmée et ne protège plus.",
			"Confirmer qu'une mise à jour a bien eu lieu, puis reprendre la référence avec argus baseline.",
			capEvidence(updated)...))
	}
	return out
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
		findings = append(findings, classifyChanged(changed)...)
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
