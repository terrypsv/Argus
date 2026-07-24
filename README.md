# Argus

**Scanner de posture de sécurité multiplateforme.** Argus audite le noyau, les
disques, les comptes, l'exposition réseau et les mécanismes de persistance d'une
machine, puis produit un rapport noté sur deux axes indépendants : la
**configuration défensive** et l'**intégrité** du système.

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
les traces que les attaquants laissent en pratique**.

Le score est une **note d'hygiène**, pas un certificat de propreté. Un scan
propre signifie « aucun problème évident détecté », jamais « cette machine est
saine ». Pour aller plus loin, il faut coupler Argus à un EDR, à une
journalisation `auditd`/Sysmon et à de l'analyse mémoire.

---

## Deux axes plutôt qu'une note

Un score unique ne peut pas répondre à deux questions différentes. Une machine
propre mais peu durcie et une machine bien configurée mais compromise ne
demandent pas la même réaction. Argus les sépare :

| Axe | Question posée | Exemples de contrôles |
| --- | --- | --- |
| **Durcissement** | Cette machine est-elle configurée pour résister à une attaque ? | sysctls, options de montage, pare-feu, chiffrement disque, UAC, SIP, configuration SSH |
| **Intégrité** | Y a-t-il des traces d'altération ? | processus adossés à un `memfd`, dérive d'empreintes SHA-256, persistance non signée, comptes UID 0 illégitimes, kernel taint, hooks `LD_PRELOAD` |

La classification se fait par préfixe d'identifiant de finding, pas par
catégorie : `kernel` contient à la fois les sysctls de durcissement et le kernel
taint, qui est une preuve d'altération. Le score global est le **minimum des
deux axes**, et une phrase de verdict traduit la situation.

Exemple sur une Kali de laboratoire :

```text
  HARDENING   59/100  E     INTEGRITY  100/100  A
  No compromise indicators, but this host is barely hardened
```

Aucun indicateur de compromission, mais un noyau peu durci et pas de pare-feu.
Un score unique aurait affiché « F », ce qui se lit comme une alerte d'intrusion.

---

## Ce qui est vérifié

| Domaine | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Durcissement noyau | sysctls, taint, `LD_PRELOAD` | SIP, extensions noyau | UAC, SMBv1 |
| Comptes | UID 0, mots de passe vides | - | administrateurs locaux (par SID) |
| Accès distant | configuration SSH | - | RDP + NLA |
| Disques | SUID/SGID, world-writable, options de montage, occupation | FileVault, occupation | BitLocker, occupation |
| Persistance | cron, systemd | LaunchAgents/Daemons | clés Run, tâches planifiées |
| Réseau | ports en écoute, pare-feu | ports, pare-feu applicatif | ports, pare-feu Windows |
| Antivirus | - | - | Defender et antivirus tiers via le Security Center |
| Processus | binaire supprimé, exécution depuis `/tmp`, `memfd` | - | - |
| Intégrité fichiers | oui | oui | oui |

Quelques détails de conception qui évitent le bruit :

- Sous Linux, un binaire remplacé par le gestionnaire de paquets n'est pas
  confondu avec un malware fileless. La vraie signature de l'exécution sans
  fichier est un exécutable adossé à un `memfd`, signalé en `CRITICAL`.
- Sous Windows, une entrée de démarrage sous `AppData` n'est suspecte que si son
  binaire ne porte **pas de signature Authenticode valide**. Une liste
  d'éditeurs autorisés serait contournée par un malware qui se nomme « Discord ».
- Le groupe Administrateurs est résolu par SID `S-1-5-32-544`, invariant quelle
  que soit la langue du système.
- La configuration SSH n'est pénalisée que si `sshd` tourne réellement.

Chaque contrôle est isolé : un contrôle qui échoue ou qui se heurte à un refus
de permission n'interrompt jamais le scan.

---

## Installation et compilation

Argus a besoin de la [chaîne d'outils Go](https://go.dev/dl/) (1.21 ou
supérieur). Aucune autre dépendance, aucun `go get`, fonctionne hors ligne.

```bash
git clone https://github.com/terrypsv/Argus.git
cd Argus
go build -o argus .        # produit ./argus (ou argus.exe sous Windows)
```

### Compilation croisée

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/argus-linux-amd64  .
GOOS=darwin  GOARCH=arm64 go build -o dist/argus-macos-arm64  .   # Apple Silicon
GOOS=windows GOARCH=amd64 go build -o dist/argus-windows.exe  .
```

`scripts/build.sh` le fait pour toutes les cibles.

### Lancement en double-clic

- Windows : `scripts\run.bat` compile si besoin, s'élève en administrateur,
  crée la baseline au premier lancement et laisse la fenêtre ouverte.
- Linux et macOS : `scripts/run.sh` fait l'équivalent avec bascule vers `sudo`.

---

## Utilisation

```text
argus [scan] [options]      Lance un scan. Affiche les deux scores.
argus baseline              Enregistre les empreintes SHA-256 des fichiers critiques.
argus accept <ID> --reason  Accepte un finding examiné comme dérogation connue.
argus unaccept <ID>         Révoque une dérogation.
argus exceptions            Liste les dérogations en cours.
argus diff <ancien> <nouveau>  Compare deux rapports JSON.
argus version               Affiche la version.
```

Sous Linux et macOS, préfixe par `sudo` pour débloquer les contrôles réservés à
root. Sous Windows, lance un terminal **administrateur** pour BitLocker,
Defender et les ruches de registre protégées.

### Un cycle complet

```bash
# 1. Empreinte de référence, sur une machine saine
sudo ./argus baseline

# 2. Scan, avec rapports JSON et Markdown
sudo ./argus scan --out ./reports

# 3. Un finding est examiné et assumé plutôt que corrigé
./argus accept BL-OFF --reason "Poste fixe, chiffrement prevu au T4" --by terry --days 90

# 4. Voir ce que l'on porte
./argus exceptions

# 5. Revenir sur la décision
./argus unaccept BL-OFF
```

### Options de scan

| Option | Effet |
| --- | --- |
| `--json <chemin>` | Écrit un rapport JSON. |
| `--md <chemin>` | Écrit un rapport Markdown. |
| `--out <dossier>` | Écrit les deux formats dans le dossier. |
| `--baseline <chemin>` | Fichier d'empreintes de référence. |
| `--exceptions <chemin>` | Fichier des dérogations. |
| `--roots <liste>` | Remplace les racines de système de fichiers scannées. |
| `--quick` | Saute les parcours de disque lents (SUID, world-writable). |
| `--no-color` | Désactive la couleur. |
| `--quiet` | Masque la progression contrôle par contrôle. |
| `--fail-under <n>` | Code de sortie 2 si le score global est inférieur à n. |
| `--fail-under-integrity <n>` | Code de sortie 3 si le score d'intégrité est inférieur à n. |

En intégration continue, `--fail-under-integrity 100` est le seuil qui a du
sens : il bloque le pipeline dès qu'un indicateur d'altération apparaît,
indépendamment du niveau de durcissement.

---

## Les dérogations

Un outil d'audit meurt le jour où l'on cesse de regarder son score parce qu'il
signale toujours la même chose. Argus permet donc d'assumer un finding - sans
jamais le masquer.

```bash
argus accept RUN-SUSP --reason "Figma livre son agent non signe, hash verifie" --by terry --days 90
```

Trois garde-fous délibérés :

- **La justification est obligatoire.** Sans `--reason`, la commande refuse. Une
  dérogation que personne ne peut expliquer six mois plus tard est pire que le
  finding qu'elle recouvre.
- **Le finding reste dans le rapport**, dans une section
  `ACCEPTED - carried knowingly, not fixed`, avec sa sévérité d'origine et sa
  justification. Le score brut, hors dérogations, est affiché à côté du score
  effectif. Une machine dérogée ne peut pas se présenter comme irréprochable.
- **L'expiration.** `--days 90` force une revue. Sans échéance, « temporaire »
  devient « permanent » en silence. Une dérogation expirée cesse de s'appliquer
  et le scan le signale.

Le fichier `argus-exceptions.json` est du JSON indenté : versionné, l'historique
des dérogations devient relisible en revue de code.

```json
{
  "exceptions": [
    {
      "id": "BL-OFF",
      "reason": "Poste fixe, chiffrement disque prevu au T4",
      "accepted_by": "terry",
      "accepted_at": "2026-07-23",
      "expires": "2026-10-21"
    }
  ]
}
```

---

## Détecter les changements

En sécurité hôte, le signal utile est rarement l'état absolu d'une machine mais
son **évolution** : un port qui s'ouvre, une entrée de démarrage qui apparaît,
une empreinte qui bouge.

```bash
argus scan --json hier.json --quiet
# ... le lendemain ...
argus scan --json aujourdhui.json --quiet
argus diff hier.json aujourdhui.json
```

Les différences sont classées en six familles : **NEW** (un problème absent du
scan précédent), **WORSENED** et **IMPROVED** (sévérité modifiée), **APPEARED**
et **GONE** (ligne entrée ou sortie d'un inventaire surveillé), **RESOLVED**
(problème corrigé ou dérogé). L'évolution des deux scores est affichée en tête.

La partie qui compte est la comparaison des **inventaires**. Quand un attaquant
s'installe, l'identifiant du finding ne change pas : `RUN-INV` reste `RUN-INV`,
avec simplement une ligne de plus. Argus compare donc ligne à ligne les
inventaires où une addition constitue elle-même un signal - ports en écoute,
entrées de démarrage, binaires SUID, membres du groupe Administrateurs,
extensions noyau, dérive d'empreintes.

Les ports de la plage dynamique IANA (≥ 49152) sont exclus de la comparaison :
les points de terminaison RPC Windows et les sockets éphémères Linux en
rebindent de nouveaux à chaque démarrage, et sans ce filtre chaque comparaison
remonterait une dizaine de changements sans signification.

### Surveillance continue

`--fail-on-change` renvoie le code de sortie 4 dès qu'un changement nécessitant
attention est détecté. Combiné à une tâche planifiée, cela transforme Argus en
détecteur de dérive plutôt qu'en photographie ponctuelle.

```bash
#!/usr/bin/env bash
# À lancer quotidiennement via cron ou une tâche planifiée.
cd /opt/argus
mv -f courant.json precedent.json 2>/dev/null || true
./argus scan --json courant.json --quiet --no-color
if [ -f precedent.json ]; then
    ./argus diff precedent.json courant.json --fail-on-change --no-color || \
        echo "Changements détectés sur $(hostname)" | mail -s "Argus" admin@exemple.fr
fi
```

---

## Vérification par le gestionnaire de paquets

Une empreinte de référence créée localement souffre du **trust on first use** :
si l'hôte était déjà compromis au moment du premier `argus baseline`, le binaire
altéré a été enregistré comme légitime et correspondra indéfiniment.

Le gestionnaire de paquets n'a pas ce défaut. Ses empreintes ont été produites
par la distribution, avant que la machine existe.

```bash
sudo ./argus scan --verify-packages --out ./reports
```

Comptez environ **2 min 20 sur une Kali complète** : chaque fichier packagé est
réhaché. C'est pour cette raison que le contrôle est optionnel plutôt que
silencieusement lent.

Trois filtres évitent le bruit :

- **Seul le drapeau `5` déclenche.** `dpkg` et `rpm` signalent aussi les écarts
  de taille, date, propriétaire et permissions, qui dérivent pour des raisons
  banales. Seule une empreinte différente prouve que le contenu a changé.
- **La documentation ne remonte jamais en alerte.** Un changelog compressé sous
  `/usr/share/doc` change d'empreinte à chaque reconstruction du paquet, et ne
  contient rien d'exécutable.
- **Les fichiers de configuration sont isolés.** Un `sshd_config` modifié est
  normal ; il est listé, jamais compté comme altération.

---

## Notation

Chaque axe part de **100**. Chaque contrôle en échec retire des points selon sa
sévérité :

| Sévérité | Pénalité |
| --- | --- |
| Critique | 35 |
| Élevée | 18 |
| Moyenne | 7 |
| Faible | 2 |
| Information | 0 |

Chaque score est borné à `[0, 100]` puis converti en note (A si ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 60, E ≥ 40, F en dessous). Les pondérations se règlent dans
[`internal/model/model.go`](internal/model/model.go), tout comme la table qui
répartit les findings entre les deux axes.

---

## Architecture

```text
main.go                     CLI : scan / baseline / accept / unaccept / exceptions
internal/
  model/     model.go       Finding, Severity, Axis, Report - le vocabulaire commun
  engine/    engine.go      exécute les contrôles, calcule les deux scores
             exceptions.go  chargement, application et révocation des dérogations
             host_*.go      chaînes noyau/plateforme par OS
  report/    console.go     rapport console coloré
             json.go        rapport JSON
             markdown.go    rapport Markdown
  checks/    util.go        helpers partagés (exec, lecture fichier, parcours borné)
             common.go      infos système et registre des contrôles
             disk.go        occupation disque multiplateforme
             integrity.go   empreintes SHA-256 et détection de dérive
             linux.go       contrôles Linux   (//go:build linux)
             windows.go     contrôles Windows (//go:build windows)
             darwin.go      contrôles macOS   (//go:build darwin)
```

### Ajouter un contrôle

Un contrôle est une fonction `func(ctx *engine.Context) []model.Finding`. On
l'écrit, puis on l'enregistre dans le `osChecks()` correspondant :

```go
func monControle(ctx *engine.Context) []model.Finding {
    if problemeDetecte {
        return []model.Finding{fail(
            "MON-001", "categorie", "Titre court et lisible",
            model.SevHigh,
            "Ce qui a ete observe.",
            "Comment corriger.",
            "ligne de preuve 1", "ligne de preuve 2",
        )}
    }
    return []model.Finding{pass("MON-001", "categorie", "Controle satisfait")}
}
```

Si le contrôle relève de l'intégrité et non du durcissement, ajoute son préfixe
d'identifiant à `integrityPrefixes` dans `model.go`.

---

## Tests

```bash
go test ./... -v
```

La suite couvre la logique pure, sans dépendance à un système d'exploitation :
classification par axe, calcul et bornage des scores, exclusion des dérogations
avec conservation du score brut, expiration et aller-retour du fichier
d'exceptions, comparaison de rapports et filtrage des ports éphémères.

Un cas mérite d'être signalé : `KRN-TAINT` relève de l'intégrité tandis que
`KRN-KERNEL-KPTR_RESTRICT` relève du durcissement, malgré leur préfixe commun.
C'est le genre de règle qui se casse silencieusement lors d'un refactoring, d'où
le test dédié.

## Intégration continue

Le dépôt exécute `go vet`, `go test`, `go build`, un scan de fumée et `gofmt`
sur Ubuntu, macOS et Windows à chaque pull request. Un projet multiplateforme
développé depuis une seule machine a besoin de ce filet.

---

## Pistes d'évolution

- Correspondance de signatures façon YARA sur les fichiers suspects
- Vérification via le gestionnaire de paquets (`dpkg --verify`, `rpm -Va`)
- Sortie NDJSON pour ingestion SIEM
- Validation des contrôles macOS sur matériel réel

Contributions bienvenues : ouvre une issue ou une pull request.

---

## Avertissement

Argus est un outil d'audit défensif. Ne l'utilise que sur des machines qui
t'appartiennent ou pour lesquelles tu disposes d'une autorisation. Il rapporte
une posture et des indicateurs ; il ne **garantit pas** qu'une machine est
saine, et ne remplace ni un EDR, ni une journalisation centralisée, ni une
réponse à incident professionnelle.

## Licence

MIT - voir [LICENSE](LICENSE).
