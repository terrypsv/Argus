# Argus

**Scanner de posture de sécurité multiplateforme.** Argus audite le noyau, les
disques, les comptes, l'exposition réseau et les mécanismes de persistance d'une
machine, puis produit un rapport noté indiquant ce qui ne va pas et comment le
corriger.

Il fonctionne sur **Linux, macOS et Windows**, se distribue sous forme d'un
**binaire unique statique sans aucune dépendance tierce** (bibliothèque standard
Go uniquement), et se lance depuis un terminal : PowerShell, le terminal intégré
de VS Code, un pipeline CI ou une tâche planifiée.

> Le nom vient d'*Argos Panoptès*, le géant aux cent yeux de la mythologie
> grecque : le gardien qui voit tout.

---

## Périmètre : mise au point honnête

Aucun outil ne peut détecter un malware *réellement indétectable* : par
définition, s'il est indétectable, il ne sera pas détecté. Ce que fait un vrai
outil d'audit hôte, c'est **augmenter le coût d'une intrusion et faire remonter
les traces que les attaquants laissent en pratique** :

- **Posture de durcissement** — le système est-il configuré pour résister
  (ASLR, pare-feu, SIP/Gatekeeper, UAC, configuration SSH, options de montage…).
- **Indicateurs de compromission (IOC)** — persistance dans cron/systemd/clés
  Run/LaunchAgents, processus tournant depuis un binaire supprimé ou depuis
  `/tmp`, hooks `LD_PRELOAD`, binaires SUID dans des emplacements inscriptibles,
  comptes UID 0 illégitimes.
- **Intégrité des fichiers** — une empreinte SHA-256 de référence sur les
  binaires critiques, pour qu'un `sshd`, `ls` ou `svchost.exe` trojanisé
  ressorte au scan suivant.
- **Surface d'attaque** — tous les ports en écoute et les services exposés.

Le score est une **note d'hygiène**, pas un certificat de propreté. Un scan
propre signifie « aucun problème évident détecté », jamais « cette machine est
saine ». Pour aller plus loin, il faut coupler Argus à un EDR, à une
journalisation `auditd`/Sysmon et à de l'analyse mémoire.

---

## Ce qui est vérifié

| Domaine | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Durcissement noyau | sysctl, taint, `LD_PRELOAD` | SIP, kexts | UAC, SMBv1 |
| Comptes | UID 0, mots de passe vides | — | administrateurs locaux |
| Accès distant | configuration SSH | — | RDP + NLA |
| Disques | SUID/SGID, world-writable, options de montage, occupation | FileVault, occupation | BitLocker, occupation |
| Persistance | cron, systemd | LaunchAgents/Daemons | clés Run, tâches planifiées |
| Réseau | ports en écoute, pare-feu | ports, pare-feu applicatif | ports, pare-feu Windows |
| Malware / AV | processus depuis binaire supprimé ou dossier temporaire | éléments de démarrage suspects | état de Defender |
| Intégrité fichiers | oui | oui | oui |

Chaque contrôle est indépendant et isolé : un contrôle qui échoue ou qui se
heurte à un refus de permission n'interrompt jamais le scan.

---

## Installation et compilation

Argus a besoin de la [chaîne d'outils Go](https://go.dev/dl/) (1.21 ou
supérieur). Aucune autre dépendance, aucun `go get`, fonctionne entièrement
hors ligne.

```bash
git clone https://github.com/terrypsv/Argus.git
cd Argus
go build -o argus .        # produit ./argus (ou argus.exe sous Windows)
```

Lancer directement depuis les sources, sans compiler :

```bash
go run . scan
```

### Compilation croisée pour toutes les plateformes

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/argus-linux-amd64  .
GOOS=darwin  GOARCH=arm64 go build -o dist/argus-macos-arm64  .   # Apple Silicon
GOOS=darwin  GOARCH=amd64 go build -o dist/argus-macos-amd64  .   # Mac Intel
GOOS=windows GOARCH=amd64 go build -o dist/argus-windows.exe  .
```

Les scripts `scripts/build.sh` (bash) et `scripts/run.ps1` (PowerShell) font ça
pour toi.

---

## Utilisation

```text
argus [scan] [options]   Lance un scan (par défaut). Affiche un rapport noté.
argus baseline           Enregistre les empreintes SHA-256 des fichiers critiques.
argus version            Affiche la version.
```

Commandes courantes :

```bash
# Aperçu rapide, sortie console colorée
argus

# Scan complet, rapports JSON + Markdown dans ./reports
argus scan --out ./reports

# Enregistrer une empreinte de référence (sur une machine saine, à refaire après
# chaque mise à jour légitime du système)
sudo argus baseline

# Contrôle CI : échouer si le score passe sous 80
argus scan --quiet --fail-under 80
```

### Options de scan

| Option | Effet |
| --- | --- |
| `--json <chemin>` | Écrit un rapport JSON. |
| `--md <chemin>` | Écrit un rapport Markdown. |
| `--out <dossier>` | Écrit les deux formats dans le dossier. |
| `--baseline <chemin>` | Fichier d'empreintes de référence. |
| `--roots <liste>` | Remplace les racines de système de fichiers scannées. |
| `--quick` | Saute les parcours de disque lents (SUID, world-writable). |
| `--no-color` | Désactive la couleur. |
| `--quiet` | Masque la progression contrôle par contrôle. |
| `--fail-under <n>` | Code de sortie 2 si le score est inférieur à n. |

### Depuis PowerShell (Windows)

```powershell
# depuis le dossier du dépôt
go run . scan
# ou compiler une fois, puis :
.\argus.exe scan --out .\reports
```

Lance PowerShell **en tant qu'administrateur** pour une couverture complète
(BitLocker, certaines ruches de registre, état de Defender).

### Depuis le terminal VS Code (toutes plateformes)

Ouvre le dossier dans VS Code, puis dans le terminal intégré :

```bash
go run . scan --out ./reports
```

Sous Linux et macOS, préfixe par `sudo` pour débloquer les contrôles réservés à
root (`/etc/shadow`, règles de pare-feu, spool cron complet, sockets en écoute).

---

## Sorties

- **Console** — résumé coloré avec score, note et findings groupés.
- **JSON** (`--json` / `--out`) — exploitable par un tableau de bord, pour
  comparer deux scans dans le temps, ou en CI.
- **Markdown** (`--md` / `--out`) — s'affiche proprement sur GitHub, à déposer
  dans un wiki ou un ticket.

### Notation

Chaque machine part de **100**. Chaque contrôle en échec retire des points selon
sa sévérité :

| Sévérité | Pénalité |
| --- | --- |
| Critique | 35 |
| Élevée | 18 |
| Moyenne | 7 |
| Faible | 2 |
| Information | 0 |

Le score est borné à `[0, 100]` puis converti en note (A si ≥ 90, jusqu'à F en
dessous de 40). Les pondérations se règlent dans
[`internal/model/model.go`](internal/model/model.go).

---

## Architecture

```text
main.go                     CLI : scan / baseline / version, options, sorties
internal/
  model/     model.go       Finding, Severity, Report — le vocabulaire commun
  engine/    engine.go      exécute les contrôles (avec récupération de panic),
                            calcule le score et la note
             host_*.go      chaînes noyau/plateforme par OS
  report/    console.go     rapport console coloré
             json.go        rapport JSON
             markdown.go    rapport Markdown
  checks/    util.go        helpers partagés (exec, lecture fichier, parcours borné)
             common.go      infos système + registre des contrôles (All())
             disk.go        occupation disque multiplateforme
             integrity.go   empreintes SHA-256 et détection de dérive
             linux.go       contrôles Linux   (//go:build linux)
             windows.go     contrôles Windows (//go:build windows)
             darwin.go      contrôles macOS   (//go:build darwin)
```

### Ajouter son propre contrôle

Un contrôle est simplement une fonction
`func(ctx *engine.Context) []model.Finding`. On l'écrit, puis on l'enregistre
dans le `osChecks()` correspondant :

```go
func monControle(ctx *engine.Context) []model.Finding {
    if problemeDetecte {
        return []model.Finding{fail(
            "MON-001", "categorie", "Titre court et lisible",
            model.SevHigh,
            "Ce qui a été observé.",
            "Comment corriger.",
            "ligne de preuve 1", "ligne de preuve 2",
        )}
    }
    return []model.Finding{pass("MON-001", "categorie", "Contrôle satisfait")}
}
```

Utilise `pass`, `fail`, `info` et `errFinding` depuis `util.go`. Garde les
contrôles sans effet de bord et rapides.

---

## Pistes d'évolution

- Correspondance de signatures façon YARA sur les fichiers suspects
- Comparaison de deux rapports JSON (`argus diff ancien.json nouveau.json`)
- Vérification via le gestionnaire de paquets (`rpm -Va`, `dpkg --verify`)
- Inventaire des paquets installés / SBOM
- Sortie NDJSON pour ingestion SIEM

Contributions bienvenues : ouvre une issue ou une pull request.

---

## Avertissement

Argus est un outil d'audit défensif. Ne l'utilise que sur des machines qui
t'appartiennent ou pour lesquelles tu disposes d'une autorisation écrite. Il
rapporte une posture et des indicateurs ; il ne **garantit pas** qu'une machine
est saine, et ne remplace ni un EDR, ni une journalisation centralisée, ni une
réponse à incident professionnelle.

## Licence

MIT — voir [LICENSE](LICENSE).
