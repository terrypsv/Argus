package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// stdinIsInteractive reports whether a human is on the other end of the input.
//
// This is the only safe gate for a prompt. A double-clicked binary gets a fresh
// console, so stdin is a character device; so is a bare `argus` typed at a
// shell. A pipeline, a scheduled task or a CI job redirects stdin, and a
// scanner that stops there to ask a question is broken.
func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// offerBrowserReport asks how the report should be presented. It runs only when
// no subcommand was given and a human is watching, so `argus scan`, `argus
// serve` and every non-interactive invocation stay untouched.
func offerBrowserReport() {
	if !stdinIsInteractive() {
		return
	}
	fmt.Print("\nArgus\n\n" +
		"  1  Rapport interactif dans le navigateur\n" +
		"  2  Rapport dans cette fenetre\n\n" +
		"Votre choix [1] : ")

	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()

	if strings.TrimSpace(line) == "2" {
		return // fall through to the console scan
	}
	os.Args = append(os.Args, "serve")
}
