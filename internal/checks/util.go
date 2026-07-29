package checks

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
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

// cap50 caps an evidence slice to 50 entries plus a summary line.
func cap50(s []string) []string {
	if len(s) <= 50 {
		return s
	}
	res := append([]string{}, s[:50]...)
	return append(res, fmt.Sprintf("... (+%d more)", len(s)-50))
}

// trunc shortens long lines for readable evidence.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
