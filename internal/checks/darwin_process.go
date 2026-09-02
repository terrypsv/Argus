//go:build darwin

package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// worldWritableExec are directories any local account can write to. A process
// executing from one of them chose an unusual place to live.
var worldWritableExec = []string{
	"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
	"/Users/Shared/", "/private/var/folders/",
}

// macProcesses looks for executables running from places software does not
// normally live.
//
// The parsing is shaped by what `ps -axo comm=` actually prints on macOS, not
// by what it prints on Linux. Two differences matter: paths contain spaces, so
// the command cannot be recovered with field splitting; and some processes are
// reported by bare name rather than by path. A bare name is not a safe result
// and not a suspicious one either, it is an unresolved one, and this check says
// so rather than quietly counting it as clean.
func macProcesses(ctx *engine.Context) []model.Finding {
	out, err := runCmd(30*time.Second, "ps", "-axo", "pid=,user=,comm=")
	if err != nil && strings.TrimSpace(out) == "" {
		return []model.Finding{errFinding("PROC-LIST", "process",
			"Could not enumerate processes",
			"ps returned nothing usable. No claim is made about running processes.")}
	}

	haveCodesign := cmdAvailable("codesign")
	var suspicious, signedTemp, vanished, unresolved []string
	total := 0

	for _, line := range strings.Split(out, "\n") {
		pid, user, cmd, ok := parsePSLine(line)
		if !ok {
			continue
		}
		total++

		if !strings.HasPrefix(cmd, "/") {
			// ps reported a bare name, so there is no path to inspect.
			unresolved = append(unresolved, fmt.Sprintf("%s (pid %s, %s)", cmd, pid, user))
			continue
		}

		// A binary that no longer exists at its own path was replaced or
		// removed while running. That is routine right after an update, and it
		// is also how a dropper cleans up after itself, so it is reported
		// without being treated as proof of anything.
		if !fileExists(cmd) {
			vanished = append(vanished, fmt.Sprintf("%s (pid %s, %s)", trunc(cmd, 90), pid, user))
			continue
		}

		if !hasAnyPrefix(cmd, worldWritableExec...) {
			continue
		}
		if haveCodesign {
			if authority, valid := signedBy(cmd); valid {
				signedTemp = append(signedTemp,
					fmt.Sprintf("%s (pid %s, signed by %s)", trunc(cmd, 80), pid, trunc(authority, 50)))
				continue
			}
		}
		suspicious = append(suspicious,
			fmt.Sprintf("%s (pid %s, %s)", trunc(cmd, 90), pid, user))
	}

	if total == 0 {
		return []model.Finding{errFinding("PROC-LIST", "process",
			"Could not parse the process list",
			"ps produced output but no line matched the expected pid/user/command shape.")}
	}

	var findings []model.Finding
	if len(suspicious) > 0 {
		findings = append(findings, fail("PROC-TEMPEXEC", "process",
			fmt.Sprintf("%d unsigned process(es) running from a world-writable directory", len(suspicious)),
			model.SevHigh,
			"Software installed normally does not execute from a temporary or shared directory, and an unsigned binary doing so has no publisher to answer for it.",
			"Identify each process before killing it; the path and parent tell you how it got there.",
			capEvidence(suspicious)...))
	}
	if len(signedTemp) > 0 {
		findings = append(findings, info("PROC-TEMPSIGNED", "process",
			fmt.Sprintf("%d signed process(es) running from a world-writable directory", len(signedTemp)),
			"Unusual placement but a valid signature, which installers and updaters legitimately produce. Listed so an unexpected one stands out.",
			capEvidence(signedTemp)...))
	}
	if len(vanished) > 0 {
		findings = append(findings, fail("PROC-VANISHED", "process",
			fmt.Sprintf("%d process(es) whose executable no longer exists", len(vanished)),
			model.SevLow,
			"Expected shortly after an update replaced the binary. Persisting across a reboot, or affecting something you did not update, is worth investigating.",
			"Compare against your recent update history.", capEvidence(vanished)...))
	}
	if len(unresolved) > 0 {
		findings = append(findings, info("PROC-UNRESOLVED", "process",
			fmt.Sprintf("%d process(es) reported without a path", len(unresolved)),
			"ps gave a bare name for these, so their executable could not be located or verified. They are neither cleared nor suspected.",
			capEvidence(unresolved)...))
	}
	if len(suspicious) == 0 && len(vanished) == 0 {
		findings = append(findings, pass("PROC-OK", "process",
			fmt.Sprintf("No process anomalies among %d running processes", total)))
	}
	return findings
}

// parsePSLine splits "  123 root  /path/with spaces/binary" into its parts.
//
// strings.Fields cannot be used for the command: macOS reports full paths, and
// those paths contain spaces. Only the first two columns are fixed.
func parsePSLine(line string) (pid, user, cmd string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", "", false
	}
	first := strings.Fields(line)
	if len(first) < 3 {
		return "", "", "", false
	}
	pid, user = first[0], first[1]
	if strings.Trim(pid, "0123456789") != "" {
		return "", "", "", false // header or noise
	}
	// Walk past the two fixed columns to keep the remainder intact.
	idx := 0
	for _, f := range []string{pid, user} {
		j := strings.Index(line[idx:], f)
		if j < 0 {
			return "", "", "", false
		}
		idx += j + len(f)
	}
	cmd = strings.TrimSpace(line[idx:])
	if cmd == "" {
		return "", "", "", false
	}
	return pid, user, cmd, true
}
