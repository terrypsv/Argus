// Installeur d'Argus pour Windows.
//
// Il pose la ligne de commande, et si l'utilisateur le veut l'application de
// bureau, sa tache d'analyse periodique et son raccourci. Il sait aussi
// verifier, reparer et desinstaller ce qu'il a pose, puisqu'il s'en recopie une
// copie dans le repertoire d'installation.
//
// Le manifeste demande les droits administrateur au lancement: tout ce que fait
// ce programme, ecrire dans Program Files, modifier le PATH systeme, declarer
// une entree de desinstallation, en a besoin. Demander a mi-chemin laisserait
// une installation a moitie faite.
package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

var version = "dev"

func main() {
	app := NouvelleApp(version)

	// Lance depuis l'entree de desinstallation de Windows, l'installeur
	// s'ouvre directement sur ce qui est demande plutot que sur son ecran
	// d'accueil.
	depart := "accueil"
	for _, a := range os.Args[1:] {
		switch a {
		case "--desinstaller":
			depart = "desinstaller"
		case "--reparer":
			depart = "reparer"
		}
	}
	app.depart = depart

	err := wails.Run(&options.App{
		Title:     "Installation d'Argus",
		Width:     880,
		Height:    580,
		MinWidth:  880,
		MinHeight: 580,
		MaxWidth:  880,
		MaxHeight: 580,

		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 8, G: 9, B: 11, A: 1},
		OnStartup:        app.demarrage,
		Bind:             []any{app},
	})
	if err != nil {
		println("l'installeur n'a pas pu demarrer:", err.Error())
	}
}
