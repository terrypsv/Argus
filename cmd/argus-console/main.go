// Console Argus: l'application de bureau.
//
// Elle ne refait pas le moteur d'analyse, elle appelle la ligne de commande et
// lit le rapport JSON qu'elle produit. Deux raisons à ce choix.
//
// La première est qu'il n'y a ainsi qu'une seule implémentation des contrôles.
// Deux moteurs finissent toujours par diverger, et deux outils qui donnent des
// notes différentes sur la même machine ne valent plus rien.
//
// La seconde est que la frontière est la sortie documentée de l'outil, pas ses
// types internes. Si le moteur réorganise ses structures demain, la console
// continue de fonctionner.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// version est posée à la compilation par -ldflags. Un binaire qui ne sait pas
// dire sa version rend un rapport irreproductible.
var version = "dev"

// dateCompilation est posée par -ldflags au format 2006-01-02.
//
// Elle sert à dire l'âge de la version installée sans contacter quoi que ce
// soit. Un outil de sécurité périmé est un problème en soi, et l'utilisateur
// visé par cette application ne pensera pas à aller vérifier lui-même.
var dateCompilation = ""

func main() {
	// Avant toute fenêtre: passé ce point, Windows a déjà décidé de l'échelle
	// d'affichage et refuse d'en changer, ce qui rend l'application floue sur
	// un écran à densité élevée.
	declarerConscienceResolution()

	app := NouvelleApp(version)

	err := wails.Run(&options.App{
		Title:     "Console Argus",
		Width:     1120,
		Height:    740,
		MinWidth:  920,
		MinHeight: 620,

		AssetServer: &assetserver.Options{Assets: assets},

		// Le fond est posé ici plutôt que dans la feuille de style: sans cela,
		// la fenêtre clignote en blanc au démarrage avant que la page ne
		// s'affiche, ce qui se voit et fait bricolage.
		BackgroundColour: &options.RGBA{R: 8, G: 9, B: 11, A: 1},

		OnStartup: app.demarrage,
		Bind:      []any{app},
	})
	if err != nil {
		println("La Console Argus n'a pas pu démarrer:", err.Error())
	}
}
