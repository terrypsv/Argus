package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// runCmd executes a command with a hard timeout and returns trimmed stdout.
// stderr is ignored on purpose: these are best-effort probes.
// runCmdCombined captures stderr as well as stdout. Some tools write their
// actual answer to stderr: codesign prints the signing authority there, so
// reading only stdout silently loses it.
func runCmdCombined(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// runCmdSeparate rend la sortie standard et la sortie d'erreur séparément.
//
// runCmd perd la seconde: Go ne la joint qu'à l'erreur, et une commande qui
// réussit n'en produit pas. Or un programme peut très bien réussir tout en
// signalant ce qu'il n'a pas pu faire, et c'est le cas des gestionnaires de
// paquets. Jeter ce canal revient à transformer une vérification partielle en
// vérification réussie.
func runCmdSeparate(timeout time.Duration, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var sortie, erreurs bytes.Buffer
	cmd.Stdout = &sortie
	cmd.Stderr = &erreurs
	err := cmd.Run()

	return strings.TrimSpace(sortie.String()), strings.TrimSpace(erreurs.String()), err
}

// cmdAvailable reports whether a binary can be found in PATH.
func cmdAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// readFile returns the file content as a string (empty on error).
func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// readLines returns the non-empty, trimmed lines of a file.
func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// suspiciousPathTokens are locations malware commonly executes from.
var suspiciousPathTokens = []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"}

// suspiciousCmdTokens are download / obfuscation primitives seen in payloads.
var suspiciousCmdTokens = []string{"curl ", "wget ", "base64 ", " nc ", "ncat ",
	"/dev/tcp/", "python -c", "perl -e", "bash -i", "mkfifo", "openssl enc"}

// walkLimited walks roots up to maxFiles entries, calling fn for each regular
// file/dir. It never follows symlinks and silently skips permission errors so a
// non-root scan still produces useful results.
func walkLimited(roots []string, maxFiles int, fn func(path string, d fs.DirEntry)) {
	count := 0
	for _, root := range roots {
		if !fileExists(root) {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			count++
			if count > maxFiles {
				return filepath.SkipAll
			}
			// Do not descend into pseudo-filesystems.
			if d.IsDir() && containsAny(path+"/", "/proc/", "/sys/", "/dev/pts/") {
				return fs.SkipDir
			}
			fn(path, d)
			return nil
		})
	}
}

// pass builds a satisfied (green) finding.
func pass(id, category, title string) model.Finding {
	return model.Finding{ID: id, Category: category, Title: title, Severity: model.SevInfo, Passed: true}
}

// fail builds an unsatisfied finding.
func fail(id, category, title string, sev model.Severity, detail, remediation string, evidence ...string) model.Finding {
	return model.Finding{
		ID: id, Category: category, Title: title, Severity: sev,
		Passed: false, Detail: detail, Remediation: remediation, Evidence: evidence,
	}
}

// info builds a neutral finding (never affects the score).
func info(id, category, title, detail string, evidence ...string) model.Finding {
	return model.Finding{
		ID: id, Category: category, Title: title, Severity: model.SevInfo,
		Passed: true, Detail: detail, Evidence: evidence,
	}
}

// errFinding records that a check could not run reliably.
func errFinding(id, category, title, errMsg string) model.Finding {
	return model.Finding{
		ID: id, Category: category, Title: title, Severity: model.SevInfo,
		Passed: false, Err: errMsg,
	}
}

// check is a thin alias so OS files read cleanly.
type check = engine.Check

// maxEvidence bounds how many supporting lines a finding carries. It sits far
// above what a console can usefully display on purpose: the JSON report is what
// `argus diff` compares, so cutting the data at display length would make any
// inventory longer than a screenful undiffable. A root certificate store holds
// over a hundred entries, and truncating it hid the very additions the diff
// exists to catch. The reporters truncate for readability instead.
const maxEvidence = 500

// evidenceOverflow marks what was dropped. It is metadata about truncation
// rather than an observation, and the diff engine skips it: its counter moves
// whenever the inventory size moves, which would report a change on every scan.
const evidenceOverflow = "... (+"

func capEvidence(s []string) []string {
	if len(s) <= maxEvidence {
		return s
	}
	res := append([]string{}, s[:maxEvidence]...)
	return append(res, fmt.Sprintf("%s%d more)", evidenceOverflow, len(s)-maxEvidence))
}

// trunc shortens long lines for readable evidence.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\u2026"
}

// hasAnyPrefix reports whether s starts with any of the given prefixes.
func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// uniqueStrings removes duplicates while preserving order.
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
