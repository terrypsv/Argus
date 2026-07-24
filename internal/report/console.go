// Package report renders a model.Report to the console, JSON and Markdown.
package report

import (
	"fmt"
	"io"
	"strings"

	"argus/internal/model"
)

// ANSI colour codes; emptied when colour is disabled.
type palette struct {
	reset, red, yellow, green, cyan, gray, bold string
}

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	// Windows consoles print escape sequences literally until asked not to.
	// Doing this here covers every reporter that uses colour.
	enableANSI()
	return palette{
		reset: "\033[0m", red: "\033[31m", yellow: "\033[33m",
		green: "\033[32m", cyan: "\033[36m", gray: "\033[90m", bold: "\033[1m",
	}
}

// Console writes a human-readable summary to w.
func Console(w io.Writer, rep model.Report, color bool) {
	p := newPalette(color)

	fmt.Fprintf(w, "\n%s%s  ARGUS  security posture report%s\n", p.bold, p.cyan, p.reset)
	fmt.Fprintf(w, "%s──────────────────────────────────────────────%s\n", p.gray, p.reset)
	fmt.Fprintf(w, "Host      : %s (%s/%s)\n", rep.Host.Hostname, rep.Host.OS, rep.Host.Arch)
	fmt.Fprintf(w, "Platform  : %s\n", rep.Host.Platform)
	fmt.Fprintf(w, "Kernel    : %s\n", rep.Host.Kernel)
	fmt.Fprintf(w, "Scanned   : %s\n", rep.FinishedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Duration  : %d ms\n\n", rep.DurationMS)

	axisColor := func(v int) string {
		switch {
		case v < 60:
			return p.red
		case v < 80:
			return p.yellow
		}
		return p.green
	}
	fmt.Fprintf(w, "  HARDENING  %s%3d/100  %s%s     INTEGRITY  %s%3d/100  %s%s\n",
		axisColor(rep.Hardening.Score)+p.bold, rep.Hardening.Score, rep.Hardening.Grade, p.reset,
		axisColor(rep.Integrity.Score)+p.bold, rep.Integrity.Score, rep.Integrity.Grade, p.reset)
	if rep.Hardening.Accepted+rep.Integrity.Accepted > 0 {
		fmt.Fprintf(w, "  %swithout the accepted exceptions: hardening %d/100 (%s), integrity %d/100 (%s)%s\n",
			p.gray, rep.Hardening.RawScore, rep.Hardening.RawGrade,
			rep.Integrity.RawScore, rep.Integrity.RawGrade, p.reset)
	}
	fmt.Fprintf(w, "  %s%s%s\n", axisColor(rep.Score), rep.Verdict, p.reset)
	fmt.Fprintf(w, "  %sCRITICAL %d  HIGH %d  MEDIUM %d  LOW %d%s\n",
		p.gray, rep.Counts["CRITICAL"], rep.Counts["HIGH"],
		rep.Counts["MEDIUM"], rep.Counts["LOW"], p.reset)
	fmt.Fprintln(w)

	// Group findings by category, failures first.
	var lastCat string
	printedFail := false
	for _, f := range rep.Findings {
		if f.Passed || f.Accepted != "" {
			continue
		}
		if f.Severity == model.SevInfo && f.Err == "" {
			continue
		}
		printedFail = true
		if f.Category != lastCat {
			fmt.Fprintf(w, "%s[%s]%s\n", p.bold, strings.ToUpper(f.Category), p.reset)
			lastCat = f.Category
		}
		printFinding(w, p, f)
	}
	if !printedFail {
		fmt.Fprintf(w, "%s  No open issues. Stay vigilant - a clean scan is not a proof of safety.%s\n", p.green, p.reset)
	}

	// Accepted findings are still real problems. They are listed apart so a
	// waiver can never be mistaken for a fix.
	if rep.Counts["accepted"] > 0 {
		fmt.Fprintf(w, "\n%s[ACCEPTED - carried knowingly, not fixed]%s\n", p.bold+p.yellow, p.reset)
		for _, f := range rep.Findings {
			if f.Accepted == "" {
				continue
			}
			fmt.Fprintf(w, "  %s%-5s %s  (%s)%s\n", p.yellow, f.Severity.String()[:4], f.Title, f.ID, p.reset)
			fmt.Fprintf(w, "        %sreason: %s%s\n", p.gray, f.Accepted, p.reset)
		}
	}

	fmt.Fprintf(w, "\n%sPassed controls: %d   |   Open issues: %d   |   Accepted: %d   |   Check errors: %d%s\n",
		p.gray, rep.Counts["passed"], rep.Counts["failed"],
		rep.Counts["accepted"], rep.Counts["errors"], p.reset)
}

func printFinding(w io.Writer, p palette, f model.Finding) {
	tag, col := "WARN", p.yellow
	switch f.Severity {
	case model.SevCritical:
		tag, col = "CRIT", p.red
	case model.SevHigh:
		tag, col = "HIGH", p.red
	case model.SevMedium:
		tag, col = "MED ", p.yellow
	case model.SevLow:
		tag, col = "LOW ", p.yellow
	}
	fmt.Fprintf(w, "  %s%s%s  %s  %s(%s)%s\n", col, tag, p.reset, f.Title, p.gray, f.ID, p.reset)
	if f.Detail != "" {
		fmt.Fprintf(w, "        %s\n", f.Detail)
	}
	for _, e := range f.Evidence {
		fmt.Fprintf(w, "        %s· %s%s\n", p.gray, e, p.reset)
	}
	if f.Remediation != "" {
		fmt.Fprintf(w, "        %s→ %s%s\n", p.cyan, f.Remediation, p.reset)
	}
	if len(f.References) > 0 {
		var refs []string
		for _, r := range f.References {
			refs = append(refs, r.String())
		}
		fmt.Fprintf(w, "        %sref: %s%s\n", p.gray, strings.Join(refs, ", "), p.reset)
	}
	if f.Err != "" {
		fmt.Fprintf(w, "        %s! %s%s\n", p.red, f.Err, p.reset)
	}
}
