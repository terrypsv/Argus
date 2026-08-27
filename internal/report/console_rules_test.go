package report

import (
	"bytes"
	"strings"
	"testing"

	"argus/internal/model"
)

// Ce fichier garde ce que l'affichage decide, pas la facon dont il le
// presente. Les couleurs, les cadres et l'ordre des lignes d'en-tete restent
// libres: figer une mise en page rend toute amelioration couteuse, et ce
// n'est pas ce qui casse.

func rendre(rep model.Report) string {
	var tampon bytes.Buffer
	Console(&tampon, rep, false)
	return tampon.String()
}

// Brief est une ligne de contrat, pas un affichage: elle existe pour qu'une
// tache planifiee la decoupe et alerte dessus. Renommer une clef casse
// l'alerte de quelqu'un sans que rien n'echoue ici.
func TestBriefEstUneLigneAnalysable(t *testing.T) {
	var tampon bytes.Buffer
	Brief(&tampon, rapportDEssai())
	ligne := tampon.String()

	if strings.Count(ligne, "\n") != 1 {
		t.Fatalf("Brief doit tenir sur une ligne: %q", ligne)
	}

	champs := map[string]string{
		"host":      "poste-01",
		"hardening": "62/C",
		"integrity": "90/A",
		"accepted":  "1",
	}
	for clef, valeur := range champs {
		attendu := clef + "=" + valeur
		if !strings.Contains(ligne, attendu) {
			t.Errorf("clef manquante ou changee: %s\nligne: %s", attendu, ligne)
		}
	}
	for _, clef := range []string{"open=", "errors=", "verdict="} {
		if !strings.Contains(ligne, clef) {
			t.Errorf("clef manquante: %s\nligne: %s", clef, ligne)
		}
	}

	// Le verdict est du texte libre, avec des espaces: sans guillemets, un
	// script qui decoupe sur l'espace le tronque.
	if !strings.Contains(ligne, `verdict="Des ecarts a corriger"`) {
		t.Errorf("le verdict doit etre entre guillemets: %s", ligne)
	}
}

// La question n'est pas combien de sockets sont ouvertes, mais combien
// repondent a une machine distante. Compter un port de loopback comme expose
// produit une alarme fausse; l'inverse produit un angle mort.
func TestExposureSplitSepareLeDistantDuLocal(t *testing.T) {
	rep := model.Report{Findings: []model.Finding{{
		ID: "NET-LISTEN", Evidence: []string{
			"tcp/22 (all interfaces)",
			"tcp/80 (all interfaces)",
			"tcp/631 (127.0.0.1)",
			"tcp/5432 (localhost)",
		},
	}}}

	open, local, ok := exposureSplit(rep)
	if !ok {
		t.Fatal("des sockets existent, le partage doit s'appliquer")
	}
	if open != 2 {
		t.Errorf("joignables = %d, want 2", open)
	}
	if local != 2 {
		t.Errorf("locaux = %d, want 2", local)
	}
}

// Une ligne d'ecoute qui n'annonce pas son interface est comptee comme
// locale. C'est le choix prudent: surestimer l'exposition remplirait le
// rapport d'alarmes fausses, et la mention "all interfaces" est ce que le
// collecteur ecrit quand il sait.
func TestUnPortSansInterfaceDeclareeEstComptePourLocal(t *testing.T) {
	rep := model.Report{Findings: []model.Finding{{
		ID: "NET-LISTEN", Evidence: []string{"tcp/22", "tcp/8080"},
	}}}

	open, local, ok := exposureSplit(rep)
	if !ok {
		t.Fatal("des sockets existent")
	}
	if open != 0 {
		t.Errorf("joignables = %d, want 0: sans mention d'interface, rien n'est declare expose", open)
	}
	if local != 2 {
		t.Errorf("locaux = %d, want 2", local)
	}
}

func TestExposureSplitSansSocket(t *testing.T) {
	// Aucun constat d'ecoute: le partage ne s'applique pas, et l'affichage
	// doit s'abstenir plutot que d'annoncer zero, qui se lirait comme une
	// mesure.
	if _, _, ok := exposureSplit(model.Report{}); ok {
		t.Error("sans constat NET-LISTEN, le partage ne doit pas s'appliquer")
	}

	vide := model.Report{Findings: []model.Finding{{ID: "NET-LISTEN"}}}
	if _, _, ok := exposureSplit(vide); ok {
		t.Error("un constat sans preuve ne doit pas produire de partage")
	}

	// Des lignes sans port ne sont pas des sockets.
	sansPort := model.Report{Findings: []model.Finding{{
		ID: "NET-LISTEN", Evidence: []string{"aucun service en ecoute"},
	}}}
	if _, _, ok := exposureSplit(sansPort); ok {
		t.Error("une ligne sans port ne doit pas compter comme socket")
	}
}

// Une exception acceptee est un vrai probleme, sciemment porte. La confondre
// avec un controle reussi ferait mentir le rapport sur la posture reelle.
func TestUneExceptionNEstJamaisMeleeAuxReussites(t *testing.T) {
	sortie := rendre(rapportDEssai())

	position := strings.Index(sortie, "ACCEPTED")
	if position < 0 {
		t.Fatal("les exceptions acceptees doivent avoir leur propre section")
	}
	if !strings.Contains(sortie, "materiel industriel incompatible") {
		t.Error("le motif de l'exception doit apparaitre: une exception sans motif est un oubli")
	}
	if !strings.Contains(sortie, "SMB1-OFF") {
		t.Error("l'identifiant de l'exception doit apparaitre")
	}

	// Elle ne doit pas figurer parmi les constats ouverts. La zone commence a
	// la premiere categorie: plus haut, le calibre la nomme deliberement avec
	// les points qu'elle fait gagner, ce qui est le contraire d'un oubli.
	debut := strings.Index(sortie, "[SSH]")
	if debut < 0 || debut > position {
		t.Fatal("la liste des constats ouverts est introuvable avant la section des exceptions")
	}
	if strings.Contains(sortie[debut:position], "SMB1-OFF") {
		t.Error("une exception acceptee ne doit pas etre listee comme un constat ouvert")
	}
}

// Le calibre annonce ce que le score doit a des renonciations plutot qu'a des
// corrections. Le taire donnerait un bon score sans dire pourquoi.
func TestLeCalibreNommeCeQuiEstRenonce(t *testing.T) {
	sortie := rendre(rapportDEssai())
	position := strings.Index(sortie, "ACCEPTED")
	if position < 0 {
		t.Fatal("section des exceptions absente")
	}

	entete := sortie[:position]
	if !strings.Contains(entete, "SMB1-OFF") {
		t.Error("le calibre doit nommer l'exception qui ameliore le score")
	}
	if !strings.Contains(entete, "waived") {
		t.Error("le calibre doit dire que ces points sont renonces, pas gagnes")
	}
}

// Un controle qui n'a pas pu tourner reste visible malgre sa gravite
// informative: c'est la meme distinction que Passed contre Err ailleurs.
func TestUnControleEnPanneResteVisible(t *testing.T) {
	sortie := rendre(rapportDEssai())

	if !strings.Contains(sortie, "EXT-READ") {
		t.Error("un controle en erreur doit apparaitre malgre sa gravite info")
	}
	// Alors qu'un info ordinaire, lui, est tu.
	if strings.Contains(sortie, "INTEG-NOBASE") {
		t.Error("un constat informatif sans erreur ne doit pas encombrer les ecarts")
	}
}

// Un rapport sans ecart ne doit pas se lire comme une garantie.
func TestAucunEcartNEstPasUnePreuveDeSurete(t *testing.T) {
	rep := rapportDEssai()
	rep.Findings = []model.Finding{
		{ID: "FW-ON", Category: "network", Title: "Pare-feu actif",
			Severity: model.SevInfo, Passed: true},
	}
	rep.Counts = map[string]int{"passed": 1}
	for i := range rep.Findings {
		rep.Findings[i].Normalise()
	}

	sortie := rendre(rep)
	if !strings.Contains(sortie, "No open issues") {
		t.Fatal("l'absence d'ecart doit etre annoncee")
	}
	if !strings.Contains(strings.ToLower(sortie), "not a proof") {
		t.Error("l'absence d'ecart ne doit pas se lire comme une preuve de surete")
	}
}

// Le decompte final est ce qu'un lecteur presse retient: il doit porter les
// quatre nombres, y compris les erreurs de controle, qui disparaitraient
// sinon d'un rapport lu en diagonale.
func TestLeResumeFinalPorteLesQuatreNombres(t *testing.T) {
	rep := rapportDEssai()
	rep.Counts["failed"] = 4
	rep.Counts["errors"] = 1

	sortie := rendre(rep)
	for _, attendu := range []string{"Passed controls", "Open issues", "Accepted", "Check errors"} {
		if !strings.Contains(sortie, attendu) {
			t.Errorf("le resume final doit porter %q", attendu)
		}
	}
}

// Sans couleur, aucune sequence d'echappement ne doit sortir: la sortie part
// dans un fichier, un ticket ou un tuyau aussi souvent que dans un terminal.
func TestSansCouleurAucuneSequenceDEchappement(t *testing.T) {
	sortie := rendre(rapportDEssai())
	if strings.Contains(sortie, "\033[") {
		t.Error("des sequences ANSI sortent alors que la couleur est desactivee")
	}
}

// Le profil de la machine change ce qui est attendu d'elle: le taire ferait
// lire un rapport de serveur comme un rapport de poste de travail.
func TestLeProfilNonStandardEstAnnonce(t *testing.T) {
	if !strings.Contains(rendre(rapportDEssai()), "serveur") {
		t.Error("un profil non standard doit apparaitre")
	}

	poste := rapportDEssai()
	poste.Profile = "workstation"
	if strings.Contains(rendre(poste), "Profile") {
		t.Error("le profil par defaut n'a pas a etre annonce")
	}
}
