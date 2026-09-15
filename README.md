<img width="762" height="184" alt="ascii-art-text" src="https://github.com/user-attachments/assets/79f8ff5e-1ade-40cd-95fb-46a50a2ea864" />


# Argus

**Bulletin de posture de sécurité d'un poste.** Argus audite le noyau, les
disques, les comptes, l'exposition réseau, les certificats de confiance et les
mécanismes de persistance d'une machine, puis rend un rapport noté sur deux axes
indépendants : le **durcissement** et l'**intégrité**.

Il fonctionne sur **Linux, macOS et Windows**, se distribue sous forme d'un
**binaire unique statique sans aucune dépendance tierce** (bibliothèque standard
Go uniquement), et s'utilise de trois façons : en ligne de commande, par un
rapport interactif dans le navigateur, ou par une application de bureau sous
Windows pour qui n'a pas envie d'apprendre des commandes.

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

La classification se fait par préfixe d'identifiant de constat, pas par
catégorie : `kernel` contient à la fois les sysctls de durcissement et le kernel
taint, qui est une preuve d'altération. Le score global est le **minimum des
deux axes**, et une phrase de verdict traduit la situation.

Exemple sur un poste Windows :

```text
  DURCISSEMENT   68/100  D
  [███████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒░]
   EXT-PERMISSIONS -18   BL-OFF -7   NET-PORT-TCP-445 -7

  INTÉGRITÉ      57/100  E
  [██████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒ ]
   INTEG-CHANGED -18   RUN-SUSP -18   INTEG-UPDATED -7
```

Un score unique aurait affiché « F », ce qui se lit comme une alerte
d'intrusion alors que la moitié des points perdus vient de réglages non faits.

---

## La signature, pour distinguer la mise à jour de l'altération

Un fichier système qui change ne dit rien par lui-même : une mise à jour et un
remplacement produisent la même empreinte différente. C'est le défaut classique
d'un contrôle d'intégrité par empreintes, et la raison pour laquelle on finit
par ignorer ses alertes.

Argus interroge donc la **signature** du fichier. Un éditeur signe ce qu'il
livre, et un attaquant ne peut pas produire cette signature sans la clé privée
de l'éditeur. Trois constats en découlent, parce qu'ils appellent trois
réactions :

| Constat | Situation | Gravité | Ce qu'il faut faire |
| --- | --- | --- | --- |
| `INTEG-TAMPERED` | modifié, **sans** signature valide | `CRITICAL` | traiter la machine comme compromise |
| `INTEG-UPDATED` | modifié, **avec** signature d'éditeur | `MEDIUM` | la référence est périmée, la reprendre |
| `INTEG-CHANGED` | signature non applicable ou non vérifiable | `HIGH` | aller vérifier soi-même |

Deux précautions gouvernent ce mécanisme.

**Seuls les exécutables sont jugés sur leur signature.** Une référence surveille
des binaires et des fichiers de configuration côte à côte, et `hosts`, `sudoers`
ou `sshd_config` n'en portent jamais. Les juger ainsi lèverait une alerte
critique sur toute machine dont ces fichiers ont été édités un jour. La détection
lit les premiers octets du fichier plutôt que son extension, un binaire Unix n'en
ayant pas.

**Une vérification qui échoue n'est pas une absence de signature.** Si l'outil
système ne répond pas, les fichiers retombent sur `INTEG-CHANGED` plutôt que
d'être déclarés non signés. Conclure autrement déclencherait une alerte critique
sur `lsass.exe` à cause d'une panne d'outillage.

---

## Ce qui est vérifié

| Domaine | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Durcissement noyau | sysctls, taint, `LD_PRELOAD` | SIP, volume système scellé, Gatekeeper, extensions noyau et système | UAC, SMBv1 |
| Comptes | UID 0, mots de passe vides | UID 0, administrateurs, compte invité | administrateurs locaux (par SID) |
| Accès distant | configuration SSH | Remote Login, Remote Management, Screen Sharing | RDP + NLA |
| Disques | SUID/SGID, world-writable, options de montage, occupation | FileVault, occupation | BitLocker, occupation |
| Persistance | cron, systemd | LaunchAgents/Daemons vérifiés par signature | clés Run, tâches planifiées |
| Réseau | ports en écoute, pare-feu | ports, pare-feu applicatif, mises à jour automatiques | ports, pare-feu Windows |
| Antivirus | - | - | Defender et antivirus tiers via le Security Center |
| Processus | binaire supprimé, exécution depuis `/tmp`, `memfd` | anomalies de processus | - |
| Certificats racine | oui | oui | oui |
| Extensions de navigateur | oui | oui | oui |
| Intégrité fichiers | oui | oui | oui |

Quelques détails de conception qui évitent le bruit :

- Sous Linux, un binaire remplacé par le gestionnaire de paquets n'est pas
  confondu avec un malware sans fichier. La vraie signature de l'exécution sans
  fichier est un exécutable adossé à un `memfd`, signalé en `CRITICAL`.
- Sous Windows, une entrée de démarrage sous `AppData` n'est suspecte que si son
  binaire ne porte **pas de signature Authenticode valide**. Une liste
  d'éditeurs autorisés serait contournée par un malware qui se nomme « Discord ».
- Sous macOS, même règle avec `codesign` : un LaunchAgent qui correspond à un
  motif de persistance n'est signalé que si son programme n'a pas de signature
  valide. Le rapport indique toujours **quel motif a déclenché**, pour qu'un faux
  positif se diagnostique sans lire le code.
- Les systèmes de fichiers synthétiques et les montages en lecture seule sont
  listés mais jamais signalés.
- Le groupe Administrateurs est résolu par SID `S-1-5-32-544`, invariant quelle
  que soit la langue du système.
- La configuration SSH n'est pénalisée que si `sshd` tourne réellement.

Chaque contrôle est isolé : un contrôle qui échoue ou qui se heurte à un refus
de permission n'interrompt jamais l'analyse, et se déclare en erreur plutôt que
de compter comme réussi. Une zone non vérifiée ne doit jamais se lire comme un
résultat propre.

---

## Installation

### Windows

L'installeur pose la ligne de commande, et si vous le voulez l'application de
bureau, son raccourci et une analyse périodique. Il sait ensuite vérifier,
réparer et désinstaller ce qu'il a posé.

Sa charge est **embarquée, non téléchargée** : il installe et répare sans réseau,
ce qui est la bonne propriété pour un outil de sécurité. On ne va pas chercher
des binaires sur Internet pendant qu'on répare une machine dont on doute.

```text
argus-installeur.exe
```

Windows demandera votre autorisation au lancement : écrire dans `Program Files`,
modifier le PATH système et déclarer une entrée de désinstallation en ont besoin.

### Debian et dérivés

```bash
sudo apt install ./argus_1.3.0_amd64.deb
argus --help
man argus
```

La désinstallation par `sudo apt remove argus` ne touche ni aux rapports, ni à la
référence d'intégrité, ni au fichier des exceptions : ce sont vos données.

### macOS

Ouvrez `argus_1.3.0_darwin_arm64.pkg`. Le paquet n'est ni signé ni notarié :
Gatekeeper le refusera au double-clic, ce qui est le régime normal pour un
éditeur inconnu. Deux issues :

```bash
# clic droit puis Ouvrir, ou bien:
sudo installer -pkg argus_1.3.0_darwin_arm64.pkg -target /
```

Pour retirer le programme :

```bash
sudo /usr/local/share/doc/argus/uninstall.sh
```

### Binaire seul

Téléchargez la version correspondant à votre machine depuis la page
[Releases](https://github.com/terrypsv/Argus/releases), puis **vérifiez son
empreinte avant de l'exécuter**. Un outil de sécurité qu'on lance sans vérifier
son intégrité est une contradiction.

```bash
# Linux et macOS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x argus-linux-amd64
./argus-linux-amd64 scan
```

```powershell
# Windows
(Get-FileHash .\argus-windows-amd64.exe -Algorithm SHA256).Hash
.\argus-windows-amd64.exe scan
```

Sur macOS, un binaire téléchargé porte l'attribut de quarantaine. Après avoir
vérifié l'empreinte :

```bash
xattr -d com.apple.quarantine argus-macos-arm64
```

### Compilation depuis les sources

Argus a besoin de la [chaîne d'outils Go](https://go.dev/dl/) déclarée dans
`go.mod`. Aucune autre dépendance, aucun `go get`, fonctionne hors ligne.

```bash
git clone https://github.com/terrypsv/Argus.git
cd Argus
go build -o argus .
```

Un binaire compilé ainsi rapporte la version `dev`. Les binaires publiés portent
leur numéro, injecté à la compilation depuis l'étiquette Git.

L'application de bureau et l'installeur sont des **modules Go distincts**, sous
`cmd/argus-console` et `installer/windows-app`. Ils portent leurs dépendances
seuls, ce qui préserve la promesse d'un moteur sans dépendance tierce. Chacun a
son script `construire.ps1`.

### Depuis les sources, sans installer

Trois scripts compilent et lancent l'outil sur place, pour essayer sans rien
poser sur la machine :

```bash
./scripts/build.sh          # compile pour les cinq cibles, dans ./dist
./scripts/run.sh            # compile si besoin, passe en sudo, analyse
```

```powershell
.\scripts\run.ps1            # compile et analyse
.\scripts\run.ps1 -Baseline  # enregistre la référence d'intégrité
.\scripts\run.bat            # équivalent en double-clic, s'élève tout seul
```

Aucun d'eux ne prend la référence d'intégrité de sa propre initiative. Ils
signalent son absence et donnent la commande : la prendre revient à déclarer la
machine saine, et ce jugement n'appartient pas à un script.

Les binaires produits ainsi rapportent la version `dev`. Le numéro est injecté
par le workflow de publication depuis l'étiquette Git.

---

## Utilisation

```text
argus                       Analyse, puis propose le rapport navigateur ou console.
argus scan [options]        Analyse, rapport console. Affiche les deux notes.
argus serve [options]       Analyse, puis rapport interactif dans le navigateur.
argus baseline              Enregistre les empreintes SHA-256 des fichiers critiques.
argus accept <ID> --reason  Assume un constat examiné, avec motif et échéance.
argus unaccept <ID>         Révoque une exception.
argus exceptions            Liste ce qui est porté sciemment.
argus diff <avant> <après>  Compare deux rapports JSON.
argus version               Affiche la version et l'éditeur.
```

Sous Linux et macOS, préfixez par `sudo` pour débloquer les contrôles réservés à
root. Sous Windows, lancez un terminal **administrateur** pour BitLocker,
Defender et les ruches de registre protégées. Sans ces droits, l'analyse tourne
quand même et le rapport signale ce qu'elle n'a pas pu lire.

### Un cycle complet

```bash
# 1. Empreinte de référence, sur une machine jugée saine
sudo ./argus baseline

# 2. Analyse, avec rapports JSON et Markdown
sudo ./argus scan --out ./rapports

# 3. Un constat est examiné et assumé plutôt que corrigé
./argus accept BL-OFF --reason "Poste fixe, chiffrement prevu au T4" --by terry --days 90

# 4. Voir ce que l'on porte
./argus exceptions
```

### Options d'analyse

| Option | Effet |
| --- | --- |
| `--json <chemin>` | Écrit un rapport JSON. |
| `--md <chemin>` | Écrit un rapport Markdown. |
| `--out <dossier>` | Écrit les deux formats dans le dossier. |
| `--baseline <chemin>` | Fichier d'empreintes de référence. |
| `--exceptions <chemin>` | Fichier des constats assumés. |
| `--roots <liste>` | Remplace les racines de système de fichiers parcourues. |
| `--profile <nom>` | Classe de machine : `workstation`, `audit`, `container`. |
| `--quick` | Saute les parcours de disque lents (SUID, world-writable). Sans effet sous Windows, où ces parcours n'existent pas. |
| `--verify-packages` | Compare chaque fichier installé aux empreintes de la distribution (Linux). |
| `--no-color` | Désactive la couleur. |
| `--quiet` | Masque la progression contrôle par contrôle. |
| `--brief` | Une ligne analysable au lieu du rapport complet. |
| `--fail-under <n>` | Code de sortie 2 si la note globale est inférieure à n. |
| `--fail-under-integrity <n>` | Code de sortie 3 si la note d'intégrité est inférieure à n. |

En intégration continue, `--fail-under-integrity 100` est le seuil qui a du
sens : il bloque le pipeline dès qu'un indicateur d'altération apparaît,
indépendamment du niveau de durcissement.

---

## La Console

Une application de bureau pour Windows, destinée à ceux qui ne sont pas à l'aise
avec les commandes. Elle ne refait pas le moteur : elle appelle la ligne de
commande et lit le rapport qu'elle publie. Il n'y a donc qu'une implémentation
des contrôles, et deux outils ne peuvent pas donner des notes différentes de la
même machine.

Sept écrans :

| Écran | Ce qu'il apporte |
| --- | --- |
| **Bulletin** | Les deux notes, expliquées en clair, et le bouton qui lance une analyse. |
| **Constats** | Chaque point relevé, ses preuves, sa remédiation, et **le bouton qui ouvre l'écran de Windows concerné**. Assumer un constat s'y fait par un formulaire. |
| **Changements** | Ce qui a bougé depuis l'analyse précédente, par famille. |
| **Historique** | La trajectoire des deux notes dans le temps, et la possibilité de rouvrir une analyse passée. |
| **Exceptions** | Ce qui est porté sciemment, trié par échéance la plus proche. |
| **Référence** | Quand elle a été prise, ce qui s'en écarte, et comment la reprendre. |
| **Paramètres** | Type de machine, élévation, conservation, emplacement des données. |

Deux principes valent d'être connus.

**Argus ne modifie rien, et la Console non plus.** Les boutons ouvrent l'écran
de Windows qui gouverne un réglage, ils ne le changent pas. Un outil d'audit qui
reconfigure la machine peut la casser, et devient surtout un moyen de la
reconfigurer : qui le pilote pilote la machine.

**La Console déclare ce qu'elle ne sait pas.** Les constats auxquels elle
n'associe aucun écran sont listés en bas de la page. Le jour où un contrôle est
ajouté au moteur sans destination correspondante, elle le dit d'elle-même.

L'élévation n'est demandée que pour l'analyse, jamais pour l'interface : faire
tourner une fenêtre entière en administrateur donnerait ces privilèges à tout ce
qu'elle affiche.

---

## Les dérogations

Un outil d'audit meurt le jour où l'on cesse de regarder sa note parce qu'il
signale toujours la même chose. Argus permet donc d'assumer un constat, sans
jamais le masquer.

```bash
argus accept RUN-SUSP --reason "Figma livre son agent non signe, hash verifie" --by terry --days 90
```

Trois garde-fous délibérés :

- **La justification est obligatoire.** Sans `--reason`, la commande refuse. Une
  dérogation que personne ne peut expliquer six mois plus tard est pire que le
  constat qu'elle recouvre.
- **Le constat reste dans le rapport**, dans une section dédiée, avec sa gravité
  d'origine et sa justification. La note brute, hors dérogations, est affichée à
  côté de la note effective. Une machine dérogée ne peut pas se présenter comme
  irréprochable.
- **L'expiration.** `--days 90` force une revue. Sans échéance, « temporaire »
  devient « permanent » en silence. Une dérogation expirée cesse de s'appliquer
  et l'analyse le signale.

Le fichier `argus-exceptions.json` est du JSON indenté : versionné, l'historique
des dérogations devient relisible en revue de code.

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

Les différences sont classées en six familles : **NOUVEAU** (un problème absent
de l'analyse précédente), **AGGRAVÉ** et **AMÉLIORÉ** (gravité modifiée),
**APPARU** et **DISPARU** (ligne entrée ou sortie d'un inventaire surveillé),
**RÉSOLU** (problème corrigé ou assumé). L'évolution des deux notes est affichée
en tête.

La partie qui compte est la comparaison des **inventaires**. Quand un attaquant
s'installe, l'identifiant du constat ne change pas : `RUN-INV` reste `RUN-INV`,
avec simplement une ligne de plus. Argus compare donc ligne à ligne les
inventaires où une addition constitue elle-même un signal : ports en écoute,
entrées de démarrage, binaires SUID, membres du groupe Administrateurs,
extensions noyau, racines de confiance, dérive d'empreintes.

Les ports de la plage dynamique IANA (≥ 49152) sont exclus de la comparaison :
les points de terminaison RPC Windows et les sockets éphémères Linux en
rebindent de nouveaux à chaque démarrage, et sans ce filtre chaque comparaison
remonterait une dizaine de changements sans signification.

`--json <fichier>` publie la comparaison dans un format lisible par un autre
programme, un tableau de bord ou un SIEM.

### Surveillance continue

`--fail-on-change` renvoie le code de sortie 4 dès qu'un changement nécessitant
attention est détecté. Combiné à une tâche planifiée, cela transforme Argus en
détecteur de dérive plutôt qu'en photographie ponctuelle. Sous Windows,
l'installeur propose de mettre en place cette tâche.

---

## Vérification par le gestionnaire de paquets

Une empreinte de référence créée localement souffre du **trust on first use** :
si l'hôte était déjà compromis au moment du premier `argus baseline`, le binaire
altéré a été enregistré comme légitime et correspondra indéfiniment.

Le gestionnaire de paquets n'a pas ce défaut. Ses empreintes ont été produites
par la distribution, avant que la machine existe.

```bash
sudo ./argus scan --verify-packages --out ./rapports
```

Comptez environ **2 min 20 sur une Kali complète** : chaque fichier packagé est
réhaché. C'est pour cette raison que le contrôle est optionnel plutôt que
silencieusement lent.

Trois filtres évitent le bruit :

- **Seul le drapeau `5` déclenche.** `dpkg` et `rpm` signalent aussi les écarts
  de taille, date, propriétaire et permissions, qui dérivent pour des raisons
  banales. Seule une empreinte différente prouve que le contenu a changé.
- **La documentation ne remonte jamais en alerte.** Un changelog compressé sous
  `/usr/share/doc` change d'empreinte à chaque reconstruction du paquet.
- **Les fichiers de configuration sont isolés.** Un `sshd_config` modifié est
  normal ; il est listé, jamais compté comme altération.

---

## Rapport interactif

`argus serve` analyse puis ouvre le rapport dans le navigateur. C'est la seule
interface visuelle disponible sur Linux et macOS, et elle reste utile partout :
sur un serveur, on analyse en SSH et on regarde le rapport sans rien installer.

Le serveur est volontairement contraint, parce que c'est un outil d'audit qui
expose un port :

- il écoute uniquement sur `127.0.0.1`, sur un port choisi par le noyau ;
- chaque requête exige un jeton aléatoire de 32 octets, comparé en temps
  constant, pour qu'aucun autre processus local ne puisse lire le rapport ;
- il s'éteint tout seul quand l'onglet est fermé ;
- la page ne charge rien de l'extérieur (`Content-Security-Policy: default-src
  'none'`), tout est embarqué dans le binaire.

Sous Linux et macOS, l'analyse exige root mais lancer un navigateur en root est
une mauvaise pratique. On analyse avec `sudo`, on écrit le JSON, on l'affiche
avec son compte :

```bash
sudo ./argus scan --json ~/argus.json
./argus serve --report ~/argus.json
```

---

## Profils de machine

Un contrôle de durcissement qu'une machine ne satisfait pas volontairement n'est
pas un échec, c'est une décision : une station d'audit a besoin de `ptrace` pour
déboguer, un conteneur ne peut pas régler les sysctls du noyau. Les noter comme
des fautes produit un résultat durablement rouge, que plus personne ne lit.

```bash
sudo ./argus scan --profile audit
```

| Profil | Pour | Dérogations |
| --- | --- | --- |
| `workstation` (défaut) | Machine polyvalente | Aucune, tout s'applique. |
| `audit` | Station de pentest ou d'analyse | ptrace, kptr, dmesg, `/tmp` et `/dev/shm` exécutables. Le pare-feu reste exigé. |
| `container` | Charge conteneurisée | sysctls noyau, options de montage et filtrage, qui relèvent de l'hôte. |

Un profil n'est **pas** un second barème. Il déclare des dérogations intégrées
qui empruntent la même mécanique que les dérogations manuelles : le constat reste
visible, porte sa justification, et la note brute affiche toujours ce que la
machine vaudrait sans lui. Une règle est verrouillée : **aucun profil ne peut
déroger un constat d'intégrité**. Une classe de machine peut assumer d'être peu
durcie, aucune n'a le droit d'être altérée.

---

## Référentiels

Un constat sans référence est une opinion ; rattaché à un contrôle publié, il
devient auditable. Chaque constat porte, quand la correspondance a été vérifiée,
ses références **MITRE ATT&CK** (que fait l'attaquant, pour corréler avec les
détections d'un SOC) et **ANSSI-BP-028** (durcissement GNU/Linux). Une
correspondance n'est ajoutée qu'après vérification dans le document publié : une
référence fausse ferait remonter une décision jusqu'à un texte qui ne dit pas
cela.

---

## Supervision

`--brief` produit une seule ligne analysable, pour une tâche planifiée qui veut
une valeur à filtrer plutôt qu'une page à lire :

```text
host=ASUS-EB-TP hardening=86/B integrity=100/A open=2 accepted=0 errors=0 verdict="..."
```

Cette sortie reste en anglais : ce sont des clés destinées à des scripts, pas du
texte destiné à être lu.

---

## Notation

Chaque axe part de **100**. Chaque contrôle en échec retire des points selon sa
gravité :

| Gravité | Pénalité |
| --- | --- |
| CRITICAL | 35 |
| HIGH | 18 |
| MEDIUM | 7 |
| LOW | 2 |
| INFO | 0 |

Les niveaux restent en anglais : c'est le vocabulaire des CVE et des référentiels
que l'on consulte ensuite, et les traduire ferait perdre la correspondance.

Chaque note est bornée à `[0, 100]` puis convertie en mention (A si ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 60, E ≥ 40, F en dessous). Les pondérations se règlent dans
[`internal/model/model.go`](internal/model/model.go), tout comme la table qui
répartit les constats entre les deux axes.

### Une décision, une pénalité

Certaines expositions sont vues par deux contrôles à la fois. Activer le partage
d'écran sous macOS déclenche `VNC-ON`, parce que le service est activé, **et**
`NET-PORT-TCP-5900`, parce que le port répond sur toutes les interfaces. Même
schéma sous Windows avec `RDP-ON` et le port 3389.

Les deux constats ne sont pas redondants : une machine peut avoir le service
actif mais filtré, cas que seul le contrôle de service voit. Mais quand les deux
déclenchent, ils décrivent un seul réglage, et « vous avez perdu 14 points parce
que deux contrôles ont remarqué la même chose » ne serait pas défendable.

Le constat de service est donc conservé, visible, avec sa gravité réelle, mais
marqué comme compté une seule fois. Il est conservé plutôt que supprimé parce
qu'il explique **pourquoi** le port est ouvert : un rapport qui énonce un
symptôme sans sa cause est moins utile.

---

## Langue

L'outil s'exprime **en français** : l'aide, l'en-tête, le verdict, les intitulés
de catégories, les soixante-cinq contrôles des trois systèmes, la comparaison et
la Console.

Trois exceptions assumées :

- les **niveaux de gravité**, vocabulaire des CVE ;
- la sortie **`--brief`**, faite de clés pour des scripts ;
- les **clés du JSON et du Markdown**, qui servent de langue pivot pour
  l'archivage et pour `argus diff`. Un rapport pris avant une traduction doit
  rester comparable à un rapport pris après.

Les catégories sont donc traduites **à l'affichage seulement**. Les noms de
réglages Apple, les directives `sshd` et les paramètres noyau restent tels quels :
ce sont les intitulés que l'opérateur verra dans son système.

Une version anglaise est prévue ([issue #56](https://github.com/terrypsv/Argus/issues/56)).

---

## Architecture

```text
main.go                     CLI : scan / baseline / accept / unaccept / diff / serve
internal/
  model/     model.go       Finding, Severity, Axis, Report - le vocabulaire commun
  engine/    engine.go      exécute les contrôles, calcule les deux notes
             exceptions.go  chargement, application et révocation des dérogations
             profiles.go    profils de machine (dérogations intégrées)
  report/    console.go     rapport console coloré, jauges, sortie brève
             json.go        rapport JSON
             markdown.go    rapport Markdown
             diff.go        comparaison de deux rapports
             diff_json.go   la même, publiée pour d'autres programmes
  webui/     webui.go       serveur local (loopback, jeton, extinction auto)
  checks/    util.go        helpers partagés
             common.go      infos système et registre des contrôles
             integrity.go   empreintes SHA-256 et classement selon la signature
             signature_*.go vérification de signature, par système
             linux.go       contrôles Linux   (//go:build linux)
             windows.go     contrôles Windows (//go:build windows)
             darwin*.go     contrôles macOS   (//go:build darwin)

cmd/argus-console/          application de bureau Windows (module distinct)
installer/windows-app/      installeur Windows (module distinct)
installer/linux/            construction du paquet Debian
installer/macos/            construction du paquet macOS
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

Deux choses à ne pas oublier :

- si le contrôle relève de l'intégrité et non du durcissement, ajoutez son
  préfixe d'identifiant à `integrityPrefixes` dans `model.go` ;
- si le constat correspond à un écran de réglages Windows, ajoutez-le à la table
  `destinations` de `cmd/argus-console/actions.go`. Sans cela la Console
  affichera le constat sans bouton, et le signalera en bas de sa page.

---

## Validation sur machines réelles

La vérification continue compile et teste sur trois systèmes, mais compiler n'est
pas exécuter. Chaque plateforme a été analysée sur une machine réelle, et c'est
ce qui a produit la moitié des correctifs du dépôt :

| Plateforme | Ce que le premier scan réel a révélé |
| --- | --- |
| Windows 11 | Defender passif signalé à tort alors qu'un antivirus tiers est actif ; groupe Administrateurs introuvable sur un système en français ; `hosts` accusé d'altération parce qu'un fichier de configuration ne porte pas de signature |
| Kali Linux | 22 faux positifs de binaires supprimés après mise à jour de paquets ; « 0 socket en écoute » annoncé alors que la table n'avait pas pu être lue |
| macOS | Démon d'éditeur signé accusé d'être une trace d'altération ; `/dev` signalé plein ; point de montage tronqué au premier espace ; énumération échouée comptée comme contrôle réussi ; Screen Sharing actif rapporté éteint parce que `launchctl` a changé de vocabulaire |

Aucun de ces défauts n'était visible à la compilation.

---

## Tests

```bash
go test ./... -count=1
```

La suite couvre la logique pure, sans dépendance à un système d'exploitation :
classification par axe, calcul et bornage des notes, exclusion des dérogations
avec conservation de la note brute, expiration et aller-retour du fichier
d'exceptions, comparaison de rapports et filtrage des ports éphémères.

Un cas mérite d'être signalé : `KRN-TAINT` relève de l'intégrité tandis que
`KRN-KERNEL-KPTR_RESTRICT` relève du durcissement, malgré leur préfixe commun.
C'est le genre de règle qui se casse silencieusement lors d'un remaniement, d'où
le test dédié.

---

## Vérification continue

Sur une demande de fusion, Linux seul, plus une compilation croisée vers Windows
et macOS qui attrape une erreur dans les fichiers sous contrainte de
compilation. Sur la branche principale et sur les étiquettes, les trois systèmes.

GitHub ne compte pas les minutes à l'identique selon le système : Linux compte
une fois, Windows deux, macOS dix, et chaque tâche est arrondie à la minute
supérieure. Lancer la matrice complète sur chaque demande de fusion épuisait le
quota en une trentaine d'allers-retours.

---

## Pistes d'évolution

- Version anglaise de l'interface
- Correspondance de signatures façon YARA sur les fichiers suspects
- Sortie NDJSON pour ingestion SIEM
- Console pour Linux et macOS
- Signature du code et notarisation, pour que les binaires s'ouvrent sans
  avertissement

---

## Avertissement

Argus est un outil d'audit défensif. Ne l'utilisez que sur des machines qui vous
appartiennent ou pour lesquelles vous disposez d'une autorisation. Il rapporte
une posture et des indicateurs ; il ne **garantit pas** qu'une machine est saine,
et ne remplace ni un EDR, ni une journalisation centralisée, ni une réponse à
incident professionnelle.

---

## Licence

**Logiciel propriétaire.** Copyright (c) 2026 Terry Passave. Tous droits
réservés.

Ce logiciel et sa documentation sont la propriété exclusive de Terry Passave.
Aucune licence, expresse ou implicite, n'est accordée. Voir [LICENSE](LICENSE).
