// Argus — cross-platform host security posture scanner.
//
// Usage:
//
//	argus                 run a scan, print the report to the console
//	argus scan [flags]    run a scan with options
//	argus baseline        record trusted hashes of critical files
//	argus version         print version
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"argus/internal/checks"
	"argus/internal/engine"
	"argus/internal/model"
	"argus/internal/report"
)

func main() {
	cmd := "scan"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...) // drop the subcommand for flag parsing
	}

	switch cmd {
	case "scan":
		os.Exit(runScan())
	case "baseline":
		os.Exit(runBaseline())
	case "version":
		fmt.Printf("Argus %s (%s/%s)\n", engine.Version, osName(), archName())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func runScan() int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonPath := fs.String("json", "", "write a JSON report to this path")
	mdPath := fs.String("md", "", "write a Markdown report to this path")
	outDir := fs.String("out", "", "write both argus-report.json and argus-report.md into this directory")
	baseline := fs.String("baseline", "argus-baseline.json", "file-integrity baseline path")
	roots := fs.String("roots", "", "comma-separated filesystem roots to scan (overrides defaults)")
	quick := fs.Bool("quick", false, "skip slow filesystem walks (SUID / world-writable)")
	noColor := fs.Bool("no-color", false, "disable coloured console output")
	quiet := fs.Bool("quiet", false, "suppress per-check progress on stderr")
	failUnder := fs.Int("fail-under", -1, "exit with code 2 if the score is below this value (for CI)")
	_ = fs.Parse(os.Args[1:])

	cfg := engine.Config{
		BaselinePath: *baseline,
		Quick:        *quick,
	}
	if *roots != "" {
		cfg.ScanRoots = splitCSV(*roots)
	}

	runner := engine.New(checks.All(), cfg)
	if *quiet {
		runner.Context().Log = nil
	}
	rep := runner.Run()

	// Console output.
	report.Console(os.Stdout, rep, useColor(*noColor))

	// Optional file outputs.
	if *outDir != "" {
		_ = os.MkdirAll(*outDir, 0o755)
		writeJSON(filepath.Join(*outDir, "argus-report.json"), rep)
		writeMD(filepath.Join(*outDir, "argus-report.md"), rep)
	}
	if *jsonPath != "" {
		writeJSON(*jsonPath, rep)
	}
	if *mdPath != "" {
		writeMD(*mdPath, rep)
	}

	if *failUnder >= 0 && rep.Score < *failUnder {
		fmt.Fprintf(os.Stderr, "\nscore %d is below threshold %d\n", rep.Score, *failUnder)
		return 2
	}
	return 0
}

func runBaseline() int {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	baseline := fs.String("baseline", "argus-baseline.json", "where to write the baseline")
	add := fs.String("add", "", "comma-separated extra files to include")
	_ = fs.Parse(os.Args[1:])

	paths := checks.DefaultCriticalPaths()
	if *add != "" {
		paths = append(paths, splitCSV(*add)...)
	}
	n, err := checks.WriteBaseline(*baseline, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline failed: %v\n", err)
		return 1
	}
	fmt.Printf("Baseline written to %s (%d files hashed).\n", *baseline, n)
	fmt.Println("Re-run `argus baseline` after any legitimate system update.")
	return 0
}

func writeJSON(path string, rep model.Report) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot write %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if err := report.JSON(f, rep); err != nil {
		fmt.Fprintf(os.Stderr, "json encode failed: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "JSON report written to %s\n", path)
}

func writeMD(path string, rep model.Report) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot write %s: %v\n", path, err)
		return
	}
	defer f.Close()
	report.Markdown(f, rep)
	fmt.Fprintf(os.Stderr, "Markdown report written to %s\n", path)
}

func osName() string   { return runtime.GOOS }
func archName() string { return runtime.GOARCH }

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func useColor(noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func usage() {
	fmt.Print(`Argus — host security posture scanner

Usage:
  argus [scan] [flags]   Run a scan (default). Prints a scored report.
  argus baseline         Record trusted SHA-256 hashes of critical files.
  argus version          Print the version.

Scan flags:
  --json <path>       Write a JSON report.
  --md <path>         Write a Markdown report.
  --out <dir>         Write both JSON and Markdown into <dir>.
  --baseline <path>   Integrity baseline file (default: argus-baseline.json).
  --roots <csv>       Override filesystem roots to scan.
  --quick             Skip slow filesystem walks.
  --no-color          Disable coloured output.
  --quiet             Hide per-check progress.
  --fail-under <n>    Exit code 2 if score < n (CI gate).

Examples:
  argus
  argus scan --out ./reports --fail-under 80
  argus baseline --add /usr/local/bin/myapp
`)
}
