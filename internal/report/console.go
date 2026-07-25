// Package report renders a model.Report to the console, JSON and Markdown.
package report

import (
	"fmt"
	"io"
	"sort"
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
	fmt.Fprintf(w, "%s  %s  -  Editeur : %s  -  %s%s\n",
		p.gray, rep.Version, rep.Author, rep.Repository, p.reset)
	fmt.Fprintf(w, "%s──────────────────────────────────────────────%s\n", p.gray, p.reset)
	fmt.Fprintf(w, "Host      : %s (%s/%s)\n", rep.Host.Hostname, rep.Host.OS, rep.Host.Arch)
	fmt.Fprintf(w, "Platform  : %s\n", rep.Host.Platform)
	fmt.Fprintf(w, "Kernel    : %s\n", rep.Host.Kernel)
	fmt.Fprintf(w, "Scanned   : %s\n", rep.FinishedAt.Format("2006-01-02 15:04:05"))
	if rep.Profile != "" && rep.Profile != "workstation" {
		fmt.Fprintf(w, "Profile   : %s%s%s\n", p.bold, rep.Profile, p.reset)
	}
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

	fmt.Fprintf(w, "  %s%s%s\n\n", axisColor(rep.Score)+p.bold, rep.Verdict, p.reset)

	gauge(w, p, "HARDENING", rep.Hardening, rep.Findings, model.AxisHardening, axisColor)
	gauge(w, p, "INTEGRITY", rep.Integrity, rep.Findings, model.AxisIntegrity, axisColor)

	fmt.Fprintf(w, "  %sCRITICAL %d  HIGH %d  MEDIUM %d  LOW %d%s",
		p.gray, rep.Counts["CRITICAL"], rep.Counts["HIGH"],
		rep.Counts["MEDIUM"], rep.Counts["LOW"], p.reset)
	if open, local, ok := exposureSplit(rep); ok {
		fmt.Fprintf(w, "%s   |   %d socket(s) reachable from the network, %d loopback-only%s",
			p.gray, open, local, p.reset)
	}
	fmt.Fprintln(w)
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
			fmt.Fprintf(w, "  %s%-5s %s  (%s)%s\n", p.yellow, f.Severity.Abbrev(), f.Title, f.ID, p.reset)
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

// gaugeWidth is the printable width of the score bar.
const gaugeWidth = 46

// gauge draws one axis as a filled scale followed by the exact deductions.
// A score nobody can decompose is a number to argue with, not a measurement to
// act on, so the bar and the list always agree.
func gauge(w io.Writer, p palette, label string, a model.AxisScore,
	findings []model.Finding, axis model.Axis, colorOf func(int) string) {

	var lost, waived []model.Finding
	for _, f := range findings {
		if f.Passed || f.Severity == model.SevInfo || model.AxisOf(f) != axis {
			continue
		}
		if f.Accepted != "" {
			waived = append(waived, f)
			continue
		}
		lost = append(lost, f)
	}
	sort.Slice(lost, func(i, j int) bool {
		return lost[i].Severity.Weight() > lost[j].Severity.Weight()
	})

	cells := func(weight float64) int {
		n := int(weight/100*gaugeWidth + 0.5)
		if n < 1 {
			n = 1
		}
		return n
	}

	var bar strings.Builder
	kept := int(float64(a.Score)/100*gaugeWidth + 0.5)
	bar.WriteString(strings.Repeat("█", kept))
	for _, f := range lost {
		bar.WriteString(strings.Repeat("▒", cells(f.Severity.Weight())))
	}
	for _, f := range waived {
		bar.WriteString(strings.Repeat("░", cells(f.Severity.Weight())))
	}
	cut := []rune(bar.String())
	if len(cut) > gaugeWidth {
		cut = cut[:gaugeWidth]
	}
	line := string(cut) + strings.Repeat(" ", gaugeWidth-len(cut))

	fmt.Fprintf(w, "  %s%-11s %s%3d/100  %s%s\n",
		p.bold, label, colorOf(a.Score), a.Score, a.Grade, p.reset)
	fmt.Fprintf(w, "  %s[%s]%s\n", colorOf(a.Score), line, p.reset)

	var items []string
	for _, f := range lost {
		items = append(items, fmt.Sprintf("%s -%g", f.ID, f.Severity.Weight()))
	}
	for _, f := range waived {
		items = append(items, fmt.Sprintf("%s (-%g waived)", f.ID, f.Severity.Weight()))
	}
	if len(items) == 0 {
		fmt.Fprintf(w, "   %sno deductions%s\n\n", p.gray, p.reset)
		return
	}
	for _, l := range wrapItems(items, 70) {
		fmt.Fprintf(w, "   %s%s%s\n", p.gray, l, p.reset)
	}
	fmt.Fprintln(w)
}

// wrapItems packs short labels into lines no wider than width.
func wrapItems(items []string, width int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		candidate := it
		if cur != "" {
			candidate = cur + "   " + it
		}
		if len([]rune(candidate)) > width && cur != "" {
			lines = append(lines, cur)
			cur = it
			continue
		}
		cur = candidate
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// exposureSplit counts listening sockets by reachability. The security question
// is not how many are open but how many answer a remote machine.
func exposureSplit(rep model.Report) (open, local int, ok bool) {
	for _, f := range rep.Findings {
		if f.ID != "NET-LISTEN" || len(f.Evidence) == 0 {
			continue
		}
		for _, e := range f.Evidence {
			if !strings.Contains(e, "/") {
				continue
			}
			if strings.Contains(e, "all interfaces") {
				open++
			} else {
				local++
			}
		}
		return open, local, open+local > 0
	}
	return 0, 0, false
}

// Brief prints one parseable line. It exists for the scheduled-scan case: a
// cron job wants a value it can grep and alert on, not a page it has to read.
func Brief(w io.Writer, rep model.Report) {
	fmt.Fprintf(w, "host=%s hardening=%d/%s integrity=%d/%s open=%d accepted=%d errors=%d verdict=%q\n",
		rep.Host.Hostname,
		rep.Hardening.Score, rep.Hardening.Grade,
		rep.Integrity.Score, rep.Integrity.Grade,
		rep.Counts["failed"], rep.Counts["accepted"], rep.Counts["errors"],
		rep.Verdict)
}
