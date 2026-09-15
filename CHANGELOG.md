# Journal des modifications

Toutes les évolutions notables d'Argus sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et les
versions [le versionnage sémantique](https://semver.org/lang/fr/).

Les rubriques disent ce qui change **pour celui qui utilise l'outil**, pas ce
qui a été poussé dans le dépôt. Un titre de commit décrit un travail, une note
de version décrit une conséquence.

## [Non publié]

## [1.3.0] - 2026-09-15

### Ajouté

- L'outil s'exprime entièrement en français: l'aide, l'en-tête, le verdict, les
  intitulés de catégories, les soixante-cinq contrôles des trois systèmes et la
  comparaison de deux analyses. Les niveaux de gravité restent en anglais, ils
  sont le vocabulaire des CVE et des référentiels que l'on consulte ensuite.
- Un fichier système modifié est désormais confronté à sa signature. Un binaire
  qui change en gardant une signature d'éditeur valide vient d'une mise à jour;
  le même binaire modifié et non signé n'en vient pas. Trois constats en
  découlent, parce qu'ils appellent trois réactions: traiter la machine comme
  compromise, reprendre la référence, ou aller vérifier soi-même.
- Une console de bureau pour Windows, pour qui n'a pas envie d'apprendre des
  commandes. Elle montre le bulletin, les constats et où les régler, ce qui a
  changé depuis la dernière analyse, l'historique des notes dans le temps, les
  constats assumés et leurs échéances, la référence d'intégrité et les
  paramètres. C'est ce que la ligne de commande ne pouvait pas faire: elle
  produit des rapports, elle ne les accumule jamais.
- Un installeur Windows. Il pose la ligne de commande seule ou avec la console,
  propose une analyse périodique, et sait ensuite vérifier, réparer et
  désinstaller. Sa charge est embarquée, non téléchargée: on ne va pas chercher
  des binaires sur Internet pendant qu'on répare une machine dont on doute.
- Paquet Debian et paquet macOS, avec page de manuel et désinstalleur.
- `argus diff --json` publie la comparaison dans un format lisible par un autre
  programme, un tableau de bord ou un SIEM.
- Un journal des modifications, dont ceci est la première entrée écrite avant
  publication plutôt qu'après.

### Modifié

- Les fichiers de configuration ne sont plus jugés sur leur signature. Une
  référence d'intégrité surveille des binaires et des fichiers de configuration
  côte à côte, et `hosts` ou `sudoers` n'en portent jamais: les juger ainsi
  levait une alerte critique sur toute machine dont ces fichiers ont été édités
  un jour.
- La ponctuation décorative de la sortie cède la place au tiret et à la flèche
  écrite. Elles se lisent partout, se retapent au clavier, et se copient dans un
  ticket sans se transformer.
- La vérification continue tient en un seul workflow: Linux sur chaque demande
  de fusion, les trois systèmes sur la branche principale. Deux workflows
  lançaient jusqu'ici le même travail.

### Corrigé

- Les traits, puces et blocs du rapport s'affichaient en caractères de
  remplacement: cent six caractères étaient abîmés dans les sources elles-mêmes,
  écrits en UTF-8 puis relus comme une page de code héritée.
- La console Windows bascule en UTF-8 au démarrage, sans quoi les accents
  devenaient illisibles.
- Le tamponnage de version visait un chemin de module obsolète. Go n'échoue pas
  sur une cible inexistante, il l'ignore: la prochaine version aurait publié des
  binaires se déclarant `dev`. Une étape le vérifie désormais avant publication.

## [1.2.1] - 2026-08-26

### Corrigé

- Un profil de couverture de tests avait été committé par mégarde.

## [1.2.0] - 2026-07-29

### Ajouté

- Audit des permissions d'extensions de navigateur. Une extension s'exécute
  après le déchiffrement TLS et après l'authentification : ni le pare-feu ni la
  supervision réseau ne voient ce qu'elle lit. Le contrôle lit les manifestes
  présents sur le disque plutôt que d'interroger une boutique, car le manifeste
  est ce que le navigateur appliquera au prochain chargement de page.
- Inventaire des certificats racine de confiance, avec distinction entre les
  ancres livrées par l'éditeur du système et celles ajoutées sur la machine.
  Une racine apparue depuis l'analyse précédente est le signal sur lequel agir.
- Détection des produits d'interception TLS parmi les racines de confiance.
- Contrôles macOS des anomalies de processus.

### Modifié

- Une même exposition n'est plus comptée deux fois. Un service et le port qui
  prouve qu'il est joignable produisent chacun leur constat, mais une seule
  déduction de score : le constat de service explique pourquoi le port est
  ouvert, le perdre laisserait le rapport énoncer un symptôme sans sa cause.

### Corrigé

- Sur Windows, les racines installées localement étaient mal distinguées de
  celles du programme de confiance de Microsoft.

## [1.1.0] - 2026-07-29

### Ajouté

- Profils de machine : poste de travail, serveur d'audit, conteneur. Le profil
  décide des exemptions applicables, ce qui évite de reprocher à un conteneur ce
  qui n'a de sens que sur un poste.
- Couverture macOS élargie : comptes, accès distant, intégrité du système,
  extensions système.

### Corrigé

- L'état des services pilotés par launchd était mal lu. La formulation de
  `launchctl` a changé entre versions de macOS, et n'en lire qu'une signalait
  chaque service comme éteint : c'est ainsi que le partage d'écran était passé
  inaperçu alors qu'il écoutait sur le port 5900.
- Les fichiers plist binaires n'étaient pas décodés, ce qui laissait passer sans
  examen exactement les fichiers qu'un attaquant est le plus susceptible
  d'écrire.
- La vérification de signature sur macOS ne rapportait aucun éditeur, la chaîne
  de certificats n'apparaissant qu'à un niveau de verbosité supérieur.
- Un plantage survenait sur certains niveaux de gravité.

## [1.0.0] - 2026-07-24

### Ajouté

- Analyse de la posture de sécurité d'un poste, sur Windows, Linux et macOS,
  restituée en deux notes distinctes : le durcissement et l'intégrité.
  L'intégrité prime, car un indice d'altération signifie que l'attaque a déjà eu
  lieu, ce qui compte davantage que n'importe quel manque de durcissement.
- Référence d'intégrité par empreintes SHA-256 des fichiers critiques, et
  comparaison à chaque analyse.
- Exceptions assumées : un constat examiné peut être accepté avec un motif, une
  date et un auteur. Il reste compté à part et n'est jamais confondu avec un
  contrôle réussi, car un renoncement n'est pas une correction.
- Comparaison de deux rapports par `argus diff`.
- Rapports JSON et Markdown, et interface web locale par `argus serve`.
- Codes de sortie exploitables par une tâche planifiée, avec seuils
  `--fail-under` et `--fail-under-integrity`.
