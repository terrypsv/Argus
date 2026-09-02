// Argus - cross-platform host security posture scanner.
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
	"time"

	"github.com/terrypsv/Argus/internal/checks"
	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
	"github.com/terrypsv/Argus/internal/report"
	"github.com/terrypsv/Argus/internal/webui"
)

func main() {
	// A double-click gives no chance to type a subcommand, so offer the choice
	// once, there and only there. From a terminal or a CI job this is silent.
	if len(os.Args) == 1 {
		offerBrowserReport()
	}
	code := run()
	// os.Exit skips deferred calls, so the pause has to happen here, after the
	// command has produced all of its output.
	pauseIfLaunchedFromExplorer()
	os.Exit(code)
}

func run() int {
	cmd := "scan"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...) // drop the subcommand for flag parsing
	}

	switch cmd {
	case "scan":
		return runScan()
	case "baseline":
		return runBaseline()
	case "accept":
		return runAccept()
	case "unaccept":
		return runUnaccept()
	case "exceptions":
		return runExceptions()
	case "diff":
		return runDiff()
	case "serve":
		return runServe()
	case "version":
		fmt.Printf("Argus %s (%s/%s)\n", engine.Version, osName(), archName())
		fmt.Printf("Editeur : %s\n%s\n", engine.Author, engine.Repository)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

func runScan() int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonPath := fs.String("json", "", "write a JSON report to this path")
	mdPath := fs.String("md", "", "write a Markdown report to this path")
	outDir := fs.String("out", "", "write both argus-report.json and argus-report.md into this directory")
	baseline := fs.String("baseline", "argus-baseline.json", "file-integrity baseline path")
	exceptions := fs.String("exceptions", "argus-exceptions.json", "file of knowingly accepted findings")
	roots := fs.String("roots", "", "comma-separated filesystem roots to scan (overrides defaults)")
	quick := fs.Bool("quick", false, "skip slow filesystem walks (SUID / world-writable)")
	profile := fs.String("profile", "workstation", "machine class: "+strings.Join(engine.ProfileNames(), ", "))
	verifyPkgs := fs.Bool("verify-packages", false, "compare every installed file against the distribution's digests (Linux, slow)")
	noColor := fs.Bool("no-color", false, "disable coloured console output")
	quiet := fs.Bool("quiet", false, "suppress per-check progress on stderr")
	brief := fs.Bool("brief", false, "print a single parseable line instead of the full report")
	failUnder := fs.Int("fail-under", -1, "exit with code 2 if the overall score is below this value (for CI)")
	failIntegrity := fs.Int("fail-under-integrity", -1, "exit with code 3 if the integrity score is below this value")
	_ = fs.Parse(os.Args[1:])

	if _, err := engine.LookupProfile(*profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg := engine.Config{
		BaselinePath:   *baseline,
		ExceptionsPath: *exceptions,
		Profile:        *profile,
		Quick:          *quick,
		VerifyPackages: *verifyPkgs,
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
	if *brief {
		report.Brief(os.Stdout, rep)
	} else {
		report.Console(os.Stdout, rep, useColor(*noColor))
	}

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

	if *failIntegrity >= 0 && rep.Integrity.Score < *failIntegrity {
		fmt.Fprintf(os.Stderr, "\nintegrity score %d is below threshold %d\n", rep.Integrity.Score, *failIntegrity)
		return 3
	}
	if *failUnder >= 0 && rep.Score < *failUnder {
		fmt.Fprintf(os.Stderr, "\nscore %d is below threshold %d\n", rep.Score, *failUnder)
		return 2
	}
	return 0
}

// runAccept records a reviewed finding as a known exception. It refuses to run
// without a reason: an acceptance nobody can justify later is worse than the
// finding it hides.
func runAccept() int {
	fs := flag.NewFlagSet("accept", flag.ExitOnError)
	exceptions := fs.String("exceptions", "argus-exceptions.json", "exception file to write to")
	reason := fs.String("reason", "", "why this finding is accepted (required)")
	by := fs.String("by", "", "who accepted it")
	days := fs.Int("days", 0, "expire the acceptance after N days (0 = never)")

	// Go's flag package stops parsing at the first positional argument, so
	// `accept BL-OFF --reason "..."` would silently discard every flag. Lift
	// the finding ID out first, then parse what remains. This accepts the ID
	// on either side of the flags.
	args := os.Args[1:]
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id = args[0]
		args = args[1:]
	}
	_ = fs.Parse(args)
	if id == "" && fs.NArg() > 0 {
		id = fs.Arg(0)
	}

	if strings.TrimSpace(id) == "" {
		fmt.Fprintln(os.Stderr, "usage: argus accept <FINDING-ID> --reason \"...\" [--by name] [--days 90]")
		return 2
	}
	id = strings.ToUpper(strings.TrimSpace(id))
	if strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(os.Stderr, "--reason is required: an undocumented exception is just a hidden risk")
		return 2
	}

	e := engine.Exception{
		ID:         id,
		Reason:     strings.TrimSpace(*reason),
		AcceptedBy: strings.TrimSpace(*by),
		AcceptedAt: time.Now().Format(engine.DateLayout),
	}
	if *days > 0 {
		e.Expires = time.Now().AddDate(0, 0, *days).Format(engine.DateLayout)
	}
	if err := engine.AddException(*exceptions, e); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write %s: %v\n", *exceptions, err)
		return 1
	}
	if e.Expires != "" {
		fmt.Printf("%s accepted until %s, recorded in %s.\n", id, e.Expires, *exceptions)
	} else {
		fmt.Printf("%s accepted (no expiry), recorded in %s.\n", id, *exceptions)
	}
	fmt.Println("It will still appear in reports, flagged as accepted, but will no longer affect the score.")
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

// runUnaccept revokes a previously accepted finding.
func runUnaccept() int {
	fs := flag.NewFlagSet("unaccept", flag.ExitOnError)
	exceptions := fs.String("exceptions", "argus-exceptions.json", "exception file to edit")

	args := os.Args[1:]
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id = args[0]
		args = args[1:]
	}
	_ = fs.Parse(args)
	if id == "" && fs.NArg() > 0 {
		id = fs.Arg(0)
	}
	if strings.TrimSpace(id) == "" {
		fmt.Fprintln(os.Stderr, "usage: argus unaccept <FINDING-ID>")
		return 2
	}

	removed, err := engine.RemoveException(*exceptions, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot update %s: %v\n", *exceptions, err)
		return 1
	}
	if !removed {
		fmt.Printf("No exception recorded for %s.\n", strings.ToUpper(id))
		return 1
	}
	fmt.Printf("%s is no longer accepted; it will count against the score again.\n", strings.ToUpper(id))
	return 0
}

// runExceptions lists what is currently being carried, expired entries included.
func runExceptions() int {
	fs := flag.NewFlagSet("exceptions", flag.ExitOnError)
	path := fs.String("exceptions", "argus-exceptions.json", "exception file to read")
	_ = fs.Parse(os.Args[1:])

	ef, err := engine.LoadExceptions(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", *path, err)
		return 1
	}
	if len(ef.Exceptions) == 0 {
		fmt.Printf("No exceptions recorded in %s.\n", *path)
		return 0
	}
	now := time.Now()
	fmt.Printf("Exceptions recorded in %s:\n\n", *path)
	for _, e := range ef.Exceptions {
		state := "active, no expiry"
		if e.Expired(now) {
			state = "EXPIRED - no longer applied"
		} else if e.Expires != "" {
			state = "expires " + e.Expires
		}
		fmt.Printf("  %-16s %s\n", e.ID, state)
		fmt.Printf("    reason : %s\n", e.Reason)
		if e.AcceptedBy != "" {
			fmt.Printf("    by     : %s on %s\n", e.AcceptedBy, e.AcceptedAt)
		}
		fmt.Println()
	}
	fmt.Println("Revoke one with: argus unaccept <FINDING-ID>")
	return 0
}

// runDiff compares two JSON reports. In host security the meaningful signal is
// rarely the absolute state - it is the change: a port that opened, an autostart
// entry that appeared, a hash that moved.
func runDiff() int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	noColor := fs.Bool("no-color", false, "disable coloured output")
	failOnChange := fs.Bool("fail-on-change", false, "exit 4 if anything requiring attention changed")

	args := os.Args[1:]
	var paths []string
	for len(paths) < 2 && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		paths = append(paths, args[0])
		args = args[1:]
	}
	_ = fs.Parse(args)
	for _, a := range fs.Args() {
		if len(paths) < 2 {
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 {
		fmt.Fprintln(os.Stderr, "usage: argus diff <ancien.json> <nouveau.json> [--fail-on-change]")
		return 2
	}

	oldRep, err := report.LoadReport(paths[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", paths[0], err)
		return 1
	}
	newRep, err := report.LoadReport(paths[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", paths[1], err)
		return 1
	}
	if oldRep.Host.Hostname != newRep.Host.Hostname {
		fmt.Fprintf(os.Stderr, "warning: comparing different hosts (%s and %s)\n",
			oldRep.Host.Hostname, newRep.Host.Hostname)
	}

	d := report.Compare(oldRep, newRep)
	report.ConsoleDiff(os.Stdout, d, useColor(*noColor))

	if *failOnChange && d.Alarming > 0 {
		return 4
	}
	return 0
}

// runServe scans, then hands the result to the local browser. The listener is
// loopback-only and token-protected: see internal/webui for why.
func runServe() int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	baseline := fs.String("baseline", "argus-baseline.json", "file-integrity baseline path")
	exceptions := fs.String("exceptions", "argus-exceptions.json", "file of knowingly accepted findings")
	quick := fs.Bool("quick", false, "skip slow filesystem walks")
	profile := fs.String("profile", "workstation", "machine class: "+strings.Join(engine.ProfileNames(), ", "))
	verifyPkgs := fs.Bool("verify-packages", false, "check installed files against the distro digests (Linux)")
	noOpen := fs.Bool("no-open", false, "print the address instead of opening a browser")
	reportPath := fs.String("report", "", "serve an existing JSON report instead of running a new scan")
	_ = fs.Parse(os.Args[1:])

	// Serving a saved report matters on Unix: the scan needs root, but running
	// a browser as root does not. Scan with sudo, write the JSON, then serve it
	// as yourself.
	if *reportPath != "" {
		rep, err := report.LoadReport(*reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", *reportPath, err)
			return 1
		}
		if err := webui.Serve(rep, os.Stdout, !*noOpen); err != nil {
			fmt.Fprintf(os.Stderr, "cannot start the local report server: %v\n", err)
			return 1
		}
		return 0
	}

	runner := engine.New(checks.All(), engine.Config{
		BaselinePath:   *baseline,
		ExceptionsPath: *exceptions,
		Profile:        *profile,
		Quick:          *quick,
		VerifyPackages: *verifyPkgs,
	})
	rep := runner.Run()

	if err := webui.Serve(rep, os.Stdout, !*noOpen); err != nil {
		fmt.Fprintf(os.Stderr, "cannot start the local report server: %v\n", err)
		return 1
	}
	return 0
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
	fmt.Print(`Argus - host security posture scanner

Usage:
  argus [scan] [flags]        Run a scan (default). Prints two scores.
  argus baseline              Record trusted SHA-256 hashes of critical files.
  argus accept <ID> --reason  Accept a reviewed finding as a known exception.
  argus unaccept <ID>         Revoke a previously accepted finding.
  argus exceptions            List what is currently being carried.
  argus diff <old> <new>      Compare two JSON reports.\n  argus serve                 Scan, then open the report in your browser.
                              --report <file> serves a saved JSON instead.
  argus version               Print the version.

Scan flags:
  --json <path>               Write a JSON report.
  --md <path>                 Write a Markdown report.
  --out <dir>                 Write both JSON and Markdown into <dir>.
  --baseline <path>           Integrity baseline file.
  --exceptions <path>         Accepted-findings file.
  --roots <csv>               Override filesystem roots to scan.
  --quick                     Skip slow filesystem walks.
  --profile <name>            Machine class: workstation, audit, container.
  --verify-packages           Check installed files against the distro digests (Linux).
  --no-color                  Disable coloured output.
  --quiet                     Hide per-check progress.
  --brief                     One parseable line instead of the full report.
  --fail-under <n>            Exit 2 if the overall score < n.
  --fail-under-integrity <n>  Exit 3 if the integrity score < n.

Accept flags:
  --reason "..."              Why it is accepted (required).
  --by <name>                 Who accepted it.
  --days <n>                  Expire the acceptance after n days.

Examples:
  argus
  argus scan --out ./reports --fail-under-integrity 100
  argus baseline --add /usr/local/bin/myapp
  argus accept RUN-SUSP --reason "Figma ships this helper unsigned" --by terry --days 90
`)
}
