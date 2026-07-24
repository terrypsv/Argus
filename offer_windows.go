//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// offerBrowserReport asks whether to show the report in a browser. It only ever
// runs on a double-click: from a terminal the console is shared with the shell,
// and a scanner that stops to ask a question inside a pipeline is broken.
func offerBrowserReport() {
	if !ownsConsole() {
		return
	}
	fmt.Print("Argus\n\n" +
		"  1  Rapport dans le navigateur (recommande)\n" +
		"  2  Rapport dans cette fenetre\n\n" +
		"Votre choix [1] : ")

	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.TrimSpace(line) {
	case "2":
		return // fall through to the console scan
	default:
		os.Args = append(os.Args, "serve")
	}
}
