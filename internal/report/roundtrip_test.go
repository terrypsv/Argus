package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/model"
)

// rapportDEssai fabrique un rapport qui exerce chaque chemin des rapporteurs:
// un echec par gravite, une exception acceptee, un controle en panne, un
// constat informatif ordinaire, et une reussite.
func rapportDEssai() model.Report {
	moment := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	rep := model.Report{
		Tool:       "argus",
		Version:    "1.2.1",
		Author:     "Terry Passave",
		Repository: "github.com/terrypsv/Argus",
		Host: model.HostInfo{
			Hostname: "poste-01", OS: "linux", Arch: "amd64",
			Kernel: "6.8.12", Platform: "Debian 12", NumCPU: 8,
		},
		StartedAt:  moment,
		FinishedAt: moment.Add(3 * time.Second),
		DurationMS: 3000,
		Score:      62,
		Grade:      "C",
		Hardening:  model.AxisScore{Score: 62, Grade: "C", Issues: 3, RawScore: 55, RawGrade: "D", Accepted: 1},
		Integrity:  model.AxisScore{Score: 90, Grade: "A", Issues: 1, RawScore: 90, RawGrade: "A"},
		Verdict:    "Des ecarts a corriger",
		Profile:    "serveur",
		Suppressed: 1,
		Counts: map[string]int{
			"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1,
			"passed": 1, "accepted": 1,
		},
		Findings: []model.Finding{
			{ID: "LNX-SSH-ROOT", Category: "ssh", Title: "Connexion root autorisee",
				Severity: model.SevCritical, Detail: "PermitRootLogin yes",
				Remediation: "Passer a no", Evidence: []string{"/etc/ssh/sshd_config:32"}},
			{ID: "NET-LISTEN", Category: "network", Title: "Services en ecoute",
				Severity: model.SevHigh, Evidence: []string{"tcp/22", "tcp/8080"}},
			{ID: "DISK-LOW-var", Category: "disk", Title: "Volume presque plein",
				Severity: model.SevMedium},
			{ID: "ACC-UID0", Category: "accounts", Title: "Second compte uid 0",
				Severity: model.SevLow, Superseded: "LNX-SSH-ROOT"},
			{ID: "INTEG-NOBASE", Category: "integrity", Title: "Aucune reference",
				Severity: model.SevInfo, Passed: true, Detail: "lancer argus baseline"},
			{ID: "EXT-READ", Category: "browser", Title: "Extensions illisibles",
				Severity: model.SevInfo, Err: "permission denied"},
			{ID: "FW-ON", Category: "network", Title: "Pare-feu actif",
				Severity: model.SevInfo, Passed: true},
			{ID: "SMB1-OFF", Category: "network", Title: "SMBv1 desactive",
				Severity: model.SevMedium, Accepted: "materiel industriel incompatible"},
		},
	}
	for i := range rep.Findings {
		rep.Findings[i].Normalise()
	}
	return rep
}

// La gravite n'est pas serialisee: seule son etiquette l'est, et LoadReport
// reconstruit le nombre. Trois maillons, et il suffit qu'un seul casse pour
// que le comparateur voie toutes les gravites a zero sans jamais echouer.
func TestLaGraviteSurvitALAllerRetour(t *testing.T) {
	original := rapportDEssai()

	chemin := filepath.Join(t.TempDir(), "rapport.json")
	fichier, err := os.Create(chemin)
	if err != nil {
		t.Fatalf("creation: %v", err)
	}
	if err := JSON(fichier, original); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	fichier.Close()

	relu, err := LoadReport(chemin)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}

	if len(relu.Findings) != len(original.Findings) {
		t.Fatalf("constats relus = %d, want %d", len(relu.Findings), len(original.Findings))
	}
	for i, avant := range original.Findings {
		apres := relu.Findings[i]
		if apres.Severity != avant.Severity {
			t.Errorf("%s: gravite = %v (%s), want %v",
				avant.ID, apres.Severity, apres.SeverityStr, avant.Severity)
		}
	}

	// Le detail du tour complet: sans cette assertion, un rapport dont toutes
	// les gravites valent zero passerait le test precedent si l'original les
	// avait toutes a zero aussi.
	var critiques int
	for _, f := range relu.Findings {
		if f.Severity == model.SevCritical {
			critiques++
		}
	}
	if critiques != 1 {
		t.Errorf("gravites critiques relues = %d, want 1", critiques)
	}
}

// Ce qui compte pour un consommateur du JSON, ce sont les noms de champs et
// le fait que la gravite y soit lisible.
func TestLeJSONPorteLEtiquetteDeGravite(t *testing.T) {
	var tampon bytes.Buffer
	if err := JSON(&tampon, rapportDEssai()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var brut map[string]any
	if err := json.Unmarshal(tampon.Bytes(), &brut); err != nil {
		t.Fatalf("sortie illisible: %v", err)
	}
	for _, champ := range []string{"tool", "version", "host", "started_at", "finished_at",
		"score", "grade", "hardening", "integrity", "verdict", "findings"} {
		if _, present := brut[champ]; !present {
			t.Errorf("champ absent du rapport: %s", champ)
		}
	}

	premier := brut["findings"].([]any)[0].(map[string]any)
	if premier["severity"] != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL", premier["severity"])
	}
	// La gravite numerique ne doit pas fuir: elle porte json:"-" precisement
	// pour qu'un consommateur ne depende pas d'un ordinal.
	if _, present := premier["Severity"]; present {
		t.Error("la gravite numerique ne doit pas etre serialisee")
	}
}

// L'echappement HTML est desactive: un rapport contient des chemins et des
// lignes de configuration, et les voir en &amp; les rend inutilisables.
func TestLeJSONNEchappePasLeHTML(t *testing.T) {
	rep := rapportDEssai()
	rep.Findings = []model.Finding{{
		ID: "X", Category: "c", Title: "t", Severity: model.SevLow,
		Evidence: []string{`ExecStart=/bin/sh -c "a && b" <in >out`},
	}}
	rep.Findings[0].Normalise()

	var tampon bytes.Buffer
	if err := JSON(&tampon, rep); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	sortie := tampon.String()
	for _, echappe := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(sortie, echappe) {
			t.Errorf("sortie echappee en HTML (%s): un chemin doit rester lisible", echappe)
		}
	}
	if !strings.Contains(sortie, `a && b`) {
		t.Error("la ligne de preuve doit apparaitre telle quelle")
	}
}

func TestUnRapportIllisibleEstUneErreurNommee(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "casse.json")
	if err := os.WriteFile(chemin, []byte("{pas du JSON"), 0o600); err != nil {
		t.Fatalf("ecriture: %v", err)
	}

	if _, err := LoadReport(chemin); err == nil {
		t.Fatal("un rapport illisible doit produire une erreur")
	} else if !strings.Contains(err.Error(), "casse.json") {
		t.Errorf("l'erreur doit nommer le fichier: %v", err)
	}

	if _, err := LoadReport(filepath.Join(t.TempDir(), "jamais.json")); err == nil {
		t.Error("un fichier absent doit produire une erreur")
	}
}
