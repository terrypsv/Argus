// Copyright (c) 2026 Terry PASSAVE. Tous droits réservés.

package engine

import "runtime/debug"

// Sans l'option -X de la publication, un binaire compilé à la main se
// déclarait « dev », et un dossier d'audit qui le cite ne disait plus de quel
// code venait l'analyse. Depuis Go 1.24, go build inscrit dans le binaire la
// version du module tirée de Git, l'étiquette si le commit en porte une, sinon
// une pseudo-version qui contient le commit, suivie de +dirty quand la copie de
// travail était modifiée. C'est exact et vérifiable, donc préférable à « dev ».
func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version = versionResolue(Version, info.Main.Version)
	}
}

// versionResolue garde la version tamponnée par -X, sinon prend celle que Go a
// inscrite pour le module. « (devel) » est ce que Go inscrit quand il ne
// connaît pas la version, avec go run ou hors d'un dépôt Git, et le binaire
// reste alors « dev ».
func versionResolue(tamponnee, module string) string {
	if tamponnee != "" && tamponnee != "dev" {
		return tamponnee
	}
	if module == "" || module == "(devel)" {
		return "dev"
	}
	return module
}
