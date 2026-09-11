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

	const (
		detailNonVerifie = "Un binaire ou une configuration surveillée diffère de la référence de confiance, et la signature de ces fichiers n'a pas pu être vérifiée. C'est attendu après une mise à jour, mais c'est aussi le signe classique d'une altération."
		fixNonVerifie    = "Comparer aux empreintes publiées par l'éditeur avant de conclure. Sur une distribution Linux, argus scan --verify-packages compare chaque fichier installé aux empreintes de la distribution."
	)

	changement := func(paths []string, detail, fix string) model.Finding {
		return fail("INTEG-CHANGED", cat,
			fmt.Sprintf("%d fichier(s) critique(s) modifié(s) depuis la référence", len(paths)),
			model.SevHigh, detail, fix, capEvidence(paths)...)
	}

	if !canVerifySignatures() {
		return []model.Finding{changement(changed, detailNonVerifie, fixNonVerifie)}
	}

	// Seuls les exécutables peuvent porter une signature. Les autres fichiers
	// sont mis de côté avant toute vérification, sinon leur absence de
	// signature se lirait comme une altération.
	var signables, configurations []string
	for _, p := range changed {
		if isSignableImage(p) {
			signables = append(signables, p)
			continue
		}
		configurations = append(configurations, p)
	}

	signed, ok := verifySignatures(signables)
	if !ok {
		return []model.Finding{changement(changed, detailNonVerifie, fixNonVerifie)}
	}

	var tampered, updated []string
	for _, p := range signables {
		if authority, isSigned := signed[strings.ToLower(p)]; isSigned {
			updated = append(updated, p+"  ["+authority+"]")
			continue
		}
		tampered = append(tampered, p)
	}

	var out []model.Finding
	if len(tampered) > 0 {
		out = append(out, fail("INTEG-TAMPERED", cat,
			fmt.Sprintf("%d exécutable(s) critique(s) modifié(s) et non signé(s)", len(tampered)),
			model.SevCritical,
			"Ces exécutables diffèrent de la référence et ne portent aucune signature valide. Un éditeur signe ce qu'il livre: un binaire système modifié sans signature n'a pas été remplacé par une mise à jour.",
			"Traiter la machine comme compromise. Ne pas reprendre la référence avant d'avoir établi d'où vient le remplacement.",
			capEvidence(tampered)...))
	}
	if len(updated) > 0 {
		out = append(out, fail("INTEG-UPDATED", cat,
			fmt.Sprintf("%d exécutable(s) critique(s) modifié(s) par une mise à jour signée", len(updated)),
			model.SevMedium,
			"Ces exécutables diffèrent de la référence mais portent une signature d'éditeur valide, ce qui correspond à une mise à jour. La référence est donc périmée et ne protège plus.",
			"Confirmer qu'une mise à jour a bien eu lieu, puis reprendre la référence avec argus baseline.",
			capEvidence(updated)...))
	}
	if len(configurations) > 0 {
		out = append(out, changement(configurations,
			"Ces fichiers diffèrent de la référence. Ce sont des fichiers de configuration, qui ne portent aucune signature: la question de l'éditeur ne s'applique pas à eux, et seul leur contenu peut trancher.",
			"Comparer chaque fichier à sa version attendue. Une ligne ajoutée au fichier hosts, une règle sudo élargie ou une directive sshd relâchée sont des altérations discrètes et durables, qu'aucune signature ne révélerait."))
	}
	return out
}

// isSignableImage indique si le fichier porte un format d'image exécutable,
// c'est-à-dire s'il peut contenir une signature.
//
// La distinction compte plus qu'il n'y paraît. Une référence d'intégrité
// surveille des binaires et des fichiers de configuration côte à côte, et un
// fichier de configuration n'a jamais porté de signature. Juger hosts ou
// sudoers sur ce critère lèverait une alerte critique sur chaque machine dont
// ces fichiers ont été édités un jour, ce qui est le moyen le plus sûr
// d'apprendre à quelqu'un à ignorer l'outil.
//
// La détection lit les premiers octets plutôt que l'extension, parce qu'un
// binaire Unix n'en a pas: /usr/bin/sudo est autant un exécutable que
// lsass.exe.
func isSignableImage(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var head [4]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}

	// PE, le format des exécutables Windows.
	if head[0] == 'M' && head[1] == 'Z' {
		return true
	}
	// ELF, celui de Linux et des BSD.
	if head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		return true
	}
	// Mach-O, celui de macOS, dans ses variantes d'ordre d'octets, plus
	// l'archive universelle qui regroupe plusieurs architectures.
	magic := uint32(head[0])<<24 | uint32(head[1])<<16 | uint32(head[2])<<8 | uint32(head[3])
	switch magic {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA:
		return true
	}
	return false
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
