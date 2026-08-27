package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"argus/internal/engine"
	"argus/internal/model"
)

// integrityCheck ne touche le systeme que par des chemins: un repertoire
// temporaire suffit a exercer chacune de ses decisions, sans rien extraire.
func atelier(t *testing.T) (dossier, reference string) {
	t.Helper()
	dossier = t.TempDir()
	return dossier, filepath.Join(dossier, "baseline.json")
}

func ecrire(t *testing.T, chemin, contenu string) string {
	t.Helper()
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatalf("ecriture de %s: %v", chemin, err)
	}
	return chemin
}

func controler(reference string) []model.Finding {
	return integrityCheck(&engine.Context{
		Config: engine.Config{BaselinePath: reference},
	})
}

func constatPar(t *testing.T, findings []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	t.Fatalf("constat %s absent, presents: %s", id, strings.Join(ids, ", "))
	return model.Finding{}
}

// Une reference absente n'est pas un systeme intact. C'est la difference
// entre "rien n'a change" et "rien n'a ete compare".
func TestAbsenceDeReferenceNEstPasUneReussite(t *testing.T) {
	_, reference := atelier(t)

	findings := controler(reference)
	if len(findings) != 1 {
		t.Fatalf("constats = %d, want 1", len(findings))
	}
	if findings[0].ID != "INTEG-NOBASE" {
		t.Fatalf("id = %q, want INTEG-NOBASE", findings[0].ID)
	}
	// Un info est neutre: il ne compte pas comme un echec, mais son detail
	// doit dire ou l'outil a cherche et quoi faire.
	if !strings.Contains(findings[0].Detail, reference) {
		t.Errorf("le chemin cherche doit figurer dans le detail: %q", findings[0].Detail)
	}
	if findings[0].Err != "" {
		t.Errorf("une reference absente n'est pas une panne du controle: %q", findings[0].Err)
	}
}

// Une reference illisible est une erreur, pas une absence de changement.
func TestReferenceCorrompueEstUneErreur(t *testing.T) {
	dossier, reference := atelier(t)
	_ = dossier
	ecrire(t, reference, "{ceci n'est pas du JSON")

	findings := controler(reference)
	if findings[0].ID != "INTEG-BADBASE" {
		t.Fatalf("id = %q, want INTEG-BADBASE", findings[0].ID)
	}
	if findings[0].Passed {
		t.Error("une reference corrompue ne doit pas se lire comme une reussite")
	}
	// Err distingue un controle qui n'a pas pu tourner d'un controle qui a
	// tourne et trouve un ecart. Les deux valent Passed=false, et les
	// confondre ferait passer une panne pour une compromission.
	if findings[0].Err == "" {
		t.Error("un controle qui n'a pas pu tourner doit renseigner Err")
	}
}

// poser fabrique une reference a partir de fichiers reels.
func poser(t *testing.T, reference string, fichiers ...string) {
	t.Helper()
	n, err := WriteBaseline(reference, fichiers)
	if err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	if n != len(fichiers) {
		t.Fatalf("%d fichier(s) enregistre(s), want %d", n, len(fichiers))
	}
}

func TestFichierIntactDonneUneReussite(t *testing.T) {
	dossier, reference := atelier(t)
	cible := ecrire(t, filepath.Join(dossier, "sshd_config"), "PermitRootLogin no\n")
	poser(t, reference, cible)

	findings := controler(reference)
	if len(findings) != 1 {
		t.Fatalf("constats = %d, want 1", len(findings))
	}
	ok := constatPar(t, findings, "INTEG-OK")
	if !ok.Passed {
		t.Error("tout concordant doit donner une reussite")
	}
}

// Un fichier modifie est le constat qui justifie le controle.
func TestFichierModifieEstSignale(t *testing.T) {
	dossier, reference := atelier(t)
	cible := ecrire(t, filepath.Join(dossier, "sshd_config"), "PermitRootLogin no\n")
	poser(t, reference, cible)

	ecrire(t, cible, "PermitRootLogin yes\n")

	change := constatPar(t, controler(reference), "INTEG-CHANGED")
	if change.Passed {
		t.Error("un fichier modifie ne peut pas etre une reussite")
	}
	if change.Err != "" {
		t.Errorf("un ecart trouve n'est pas une panne du controle: %q", change.Err)
	}
	if change.Severity != model.SevHigh {
		t.Errorf("gravite = %v, want high", change.Severity)
	}
	if !strings.Contains(strings.Join(change.Evidence, " "), "sshd_config") {
		t.Errorf("le fichier doit figurer en preuve: %v", change.Evidence)
	}
	if change.Remediation == "" {
		t.Error("un fichier modifie doit dire quoi faire")
	}
}

// Disparu et modifie ne sont ni la meme gravite ni le meme geste.
func TestFichierDisparuEstDistinctDeModifie(t *testing.T) {
	dossier, reference := atelier(t)
	modifie := ecrire(t, filepath.Join(dossier, "modifie.conf"), "avant\n")
	disparu := ecrire(t, filepath.Join(dossier, "disparu.conf"), "present\n")
	poser(t, reference, modifie, disparu)

	ecrire(t, modifie, "apres\n")
	if err := os.Remove(disparu); err != nil {
		t.Fatalf("suppression: %v", err)
	}

	findings := controler(reference)
	change := constatPar(t, findings, "INTEG-CHANGED")
	manque := constatPar(t, findings, "INTEG-MISSING")

	if change.Severity == manque.Severity {
		t.Error("modifie et disparu ne doivent pas porter la meme gravite")
	}
	if manque.Severity != model.SevMedium {
		t.Errorf("gravite du disparu = %v, want medium", manque.Severity)
	}
	if !strings.Contains(strings.Join(manque.Evidence, " "), "disparu.conf") {
		t.Errorf("preuve = %v", manque.Evidence)
	}
	if len(findings) != 2 {
		t.Errorf("constats = %d, want 2: aucune reussite ne doit accompagner un ecart", len(findings))
	}
}

// Un fichier illisible n'est pas un fichier modifie. Confondre les deux
// produirait une alerte a chaque scan lance sans les droits necessaires, et
// une alerte permanente est une alerte que plus personne ne lit.
func TestFichierIllisibleNEstPasUnChangement(t *testing.T) {
	dossier, reference := atelier(t)
	cible := ecrire(t, filepath.Join(dossier, "secret.conf"), "contenu\n")
	poser(t, reference, cible)

	// Remplacer le fichier par un repertoire: illisible de la meme facon sur
	// les trois systemes, la ou chmod 000 ne prouve rien sous Windows.
	if err := os.Remove(cible); err != nil {
		t.Fatalf("suppression: %v", err)
	}
	if err := os.Mkdir(cible, 0o700); err != nil {
		t.Fatalf("creation du repertoire: %v", err)
	}

	findings := controler(reference)
	for _, f := range findings {
		if f.ID == "INTEG-CHANGED" {
			t.Errorf("un fichier illisible a ete compte comme modifie: %v", f.Evidence)
		}
	}
}

// WriteBaseline ignore ce qui n'existe pas plutot que d'echouer: une liste de
// chemins critiques couvre plusieurs systemes, et la moitie n'existe jamais
// sur une machine donnee.
func TestLaReferenceIgnoreLesCheminsAbsents(t *testing.T) {
	dossier, reference := atelier(t)
	present := ecrire(t, filepath.Join(dossier, "present.conf"), "x\n")

	n, err := WriteBaseline(reference, []string{present, filepath.Join(dossier, "jamais.conf")})
	if err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	if n != 1 {
		t.Fatalf("fichiers enregistres = %d, want 1", n)
	}

	brut, err := os.ReadFile(reference)
	if err != nil {
		t.Fatalf("lecture: %v", err)
	}
	var b baseline
	if err := json.Unmarshal(brut, &b); err != nil {
		t.Fatalf("reference illisible: %v", err)
	}
	if b.Algorithm != "sha256" {
		t.Errorf("algorithme = %q", b.Algorithm)
	}
	if len(b.Files) != 1 {
		t.Errorf("empreintes = %d, want 1", len(b.Files))
	}
}

// La reference porte les empreintes de fichiers sensibles: sur un systeme
// POSIX, elle ne doit pas etre lisible par d'autres comptes.
//
// Le test ne tourne pas sous Windows, et pas par commodite: les bits POSIX y
// sont ignores, os.WriteFile rend 0666 quel que soit le mode demande, et le
// controle d'acces passe par des listes que ce test ne sait pas lire. Le
// sauter en silence laisserait croire que la protection existe partout, donc
// il l'annonce.
func TestLaReferenceEstEcriteEnAccesRestreint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("droits POSIX ignores sous Windows: la protection y repose sur les ACL du profil")
	}

	dossier, reference := atelier(t)
	poser(t, reference, ecrire(t, filepath.Join(dossier, "x.conf"), "x\n"))

	info, err := os.Stat(reference)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("droits = %o, la reference ne doit pas etre lisible par d'autres", mode)
	}
}
