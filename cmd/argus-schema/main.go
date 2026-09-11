// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized copying prohibited.

// Commande argus-schema: convertit un rapport JSON produit par `argus scan -json`
// vers le schema de constat partage, lisible par Acta. Volontairement separee de
// la CLI principale pour ne rien toucher a main.go.
//
// Usage:
//
//	argus scan -json argus.json
//	argus-schema argus.json argus-schema.json   (ou sans 2e argument: sortie standard)
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/terrypsv/Argus/internal/report"
	"github.com/terrypsv/Argus/internal/schema"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: argus-schema <rapport-argus.json> [sortie.json]")
		os.Exit(2)
	}

	rep, err := report.LoadReport(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "lecture %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	data, err := json.MarshalIndent(schema.ToSchema(&rep), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encodage: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if len(os.Args) >= 3 {
		if err := os.WriteFile(os.Args[2], data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "ecriture %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "rapport partage ecrit dans %s\n", os.Args[2])
		return
	}
	os.Stdout.Write(data)
}
