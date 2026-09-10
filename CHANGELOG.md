# Journal des modifications

Toutes les évolutions notables d'Argus sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et les
versions [le versionnage sémantique](https://semver.org/lang/fr/).

Les rubriques disent ce qui change **pour celui qui utilise l'outil**, pas ce
qui a été poussé dans le dépôt. Un titre de commit décrit un travail, une note
de version décrit une conséquence.

## [Non publié]

### Modifié

- L'outil s'exprime entièrement en français : l'aide, l'en-tête, le verdict, les
  intitulés de catégories et les soixante-cinq contrôles des trois systèmes.
  Auparavant un même écran mélangeait deux langues, un seul contrôle étant en
  français et tous les autres en anglais.
- Les niveaux de gravité restent en anglais. `CRITICAL`, `HIGH`, `MEDIUM` et
  `LOW` sont le vocabulaire des CVE et des référentiels, et les traduire ferait
  perdre la correspondance avec les sources que l'opérateur consulte ensuite.
- Les intitulés de catégories sont traduits à l'affichage seulement. Le champ
  `Category` sert de clé dans le JSON et le Markdown, et `argus diff` compare
  deux rapports sur ces clés : traduire la donnée rendrait incomparable un
  rapport pris avant avec un rapport pris après.
- La vérification continue tient en un seul workflow. Sur une demande de fusion,
  Linux seul plus une compilation croisée vers Windows et macOS ; sur `main` et
  sur les étiquettes, les trois systèmes. Deux workflows lançaient jusqu'ici le
  même travail, et le cycle complet passe de soixante-six à dix-huit minutes.

### Corrigé

- Les traits, puces, flèches et blocs qui composent le rapport s'affichaient en
  caractères de remplacement. Cent six caractères étaient abîmés dans les
  sources elles-mêmes, écrits en UTF-8 puis relus comme une page de code
  héritée. Ils sont réécrits en points de code Unicode, que le compilateur lit
  identiquement quel que soit l'encodage du fichier.
- La console Windows bascule en UTF-8 au démarrage, faute de quoi une console en
  page de code héritée rendait les accents en caractères de remplacement.
- Deux commandes de l'aide étaient collées sur la même ligne, un retour à la
  ligne n'ayant pas été interprété.
- Un binaire de dix mégaoctets avait été committé par mégarde ; les binaires
  compilés localement sont désormais ignorés.

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
