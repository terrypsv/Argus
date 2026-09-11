package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/terrypsv/Argus/internal/model"
)

// Kinds of difference between two scans.
const (
	KindNew         = "new"
	KindResolved    = "resolved"
	KindWorse       = "worse"
	KindBetter      = "better"
	KindAppeared    = "appeared"
	KindDisappeared = "disappeared"
)

// watchedInventories are findings whose evidence list is an inventory, where a
// new line is itself the security signal. The finding ID never changes - a port
// that opens or an autostart entry that appears only shows up inside it. This
// is where an intrusion is usually visible first.
var watchedInventories = map[string]bool{
	"NET-LISTEN": true, "RUN-INV": true, "RUN-SIGNED": true, "RUN-SUSP": true,
	"SUID-INV": true, "SUID-SUSP": true, "LA-INV": true, "LA-SUSP": true,
	"TASK-SUSP": true, "CRON-SUSP": true, "SVC-SUSP": true,
	"PROC-DELETED": true, "PROC-TEMPEXEC": true, "PROC-MEMFD": true,
	"ADM-LIST": true, "ACC-UID0": true, "INTEG-CHANGED": true, "KEXT-3RD": true,
	"CERT-ROOT-INV": true, "CERT-LOCAL": true, "CERT-INTERCEPT": true,
}

// Change is one difference between two scans.
type Change struct {
	Kind     string         `json:"kind"`
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Title    string         `json:"title"`
	Severity model.Severity `json:"-"`
	Line     string         `json:"line,omitempty"` // evidence line, for appeared/disappeared
	Alarming bool           `json:"alarming"`
}

// Diff is the full comparison of two reports.
type Diff struct {
	Old      model.Report
	New      model.Report
	Changes  []Change
	Alarming int
}

// LoadReport reads a JSON report produced by a previous scan.
func LoadReport(path string) (model.Report, error) {
	var rep model.Report
	raw, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("%s: %w", path, err)
	}
	// Severity is serialised as a label; restore the numeric value.
	for i := range rep.Findings {
		rep.Findings[i].Severity = model.SeverityFromString(rep.Findings[i].SeverityStr)
	}
	return rep, nil
}

// noisyEvidence reports whether an evidence line changes so often that diffing
// it yields noise rather than signal. Windows RPC and Linux ephemeral sockets
// bind a fresh port from the dynamic range on every boot, so those additions
// mean nothing.
func noisyEvidence(id, line string) bool {
	// "... (+N more)" stands in for truncated entries. Its counter moves with
	// the inventory size, so comparing it would report a change on every scan
	// where anything at all moved, and drown the entry that actually appeared.
	if strings.HasPrefix(strings.TrimSpace(line), "... (+") {
		return true
	}
	if id != "NET-LISTEN" {
		return false
	}
	i := strings.Index(line, "tcp/")
	if i < 0 {
		return false
	}
	rest := line[i+4:]
	if end := strings.IndexAny(rest, " ("); end > 0 {
		rest = rest[:end]
	}
	p, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		return false
	}
	return p >= 49152 // IANA dynamic / private range
}

// Compare produces the ordered list of differences between two scans.
func Compare(oldRep, newRep model.Report) Diff {
	d := Diff{Old: oldRep, New: newRep}

	oldByID := map[string]model.Finding{}
	for _, f := range oldRep.Findings {
		oldByID[f.ID] = f
	}
	newByID := map[string]model.Finding{}
	for _, f := range newRep.Findings {
		newByID[f.ID] = f
	}

	// An accepted finding is not an open problem: waiving one should read as a
	// resolution in the diff, not linger as an unchanged failure.
	isProblem := func(f model.Finding) bool {
		return !f.Passed && f.Severity != model.SevInfo && f.Accepted == ""
	}

	// Appeared or changed severity.
	for _, nf := range newRep.Findings {
		of, existed := oldByID[nf.ID]
		if !isProblem(nf) {
			continue
		}
		if !existed || !isProblem(of) {
			d.Changes = append(d.Changes, Change{
				Kind: KindNew, ID: nf.ID, Category: nf.Category,
				Title: nf.Title, Severity: nf.Severity, Alarming: true,
			})
			continue
		}
		switch {
		case nf.Severity > of.Severity:
			d.Changes = append(d.Changes, Change{
				Kind: KindWorse, ID: nf.ID, Category: nf.Category,
				Title:    fmt.Sprintf("%s (%s -> %s)", nf.Title, of.Severity, nf.Severity),
				Severity: nf.Severity, Alarming: true,
			})
		case nf.Severity < of.Severity:
			d.Changes = append(d.Changes, Change{
				Kind: KindBetter, ID: nf.ID, Category: nf.Category,
				Title:    fmt.Sprintf("%s (%s \u2192 %s)", nf.Title, of.Severity, nf.Severity),
				Severity: nf.Severity,
			})
		}
	}

	// Resolved.
	for _, of := range oldRep.Findings {
		if !isProblem(of) {
			continue
		}
		nf, still := newByID[of.ID]
		if !still || !isProblem(nf) {
			d.Changes = append(d.Changes, Change{
				Kind: KindResolved, ID: of.ID, Category: of.Category,
				Title: of.Title, Severity: of.Severity,
			})
		}
	}

	// Evidence-level changes on watched inventories.
	for _, nf := range newRep.Findings {
		if !watchedInventories[nf.ID] {
			continue
		}
		of, existed := oldByID[nf.ID]
		if !existed {
			continue
		}
		before, after := map[string]bool{}, map[string]bool{}
		for _, l := range of.Evidence {
			if !noisyEvidence(of.ID, l) {
				before[l] = true
			}
		}
		for _, l := range nf.Evidence {
			if !noisyEvidence(nf.ID, l) {
				after[l] = true
			}
		}
		var added, removed []string
		for l := range after {
			if !before[l] {
				added = append(added, l)
			}
		}
		for l := range before {
			if !after[l] {
				removed = append(removed, l)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		for _, l := range added {
			d.Changes = append(d.Changes, Change{
				Kind: KindAppeared, ID: nf.ID, Category: nf.Category,
				Title: nf.Title, Line: l, Alarming: true,
			})
		}
		for _, l := range removed {
			d.Changes = append(d.Changes, Change{
				Kind: KindDisappeared, ID: nf.ID, Category: nf.Category,
				Title: nf.Title, Line: l,
			})
		}
	}

	for _, c := range d.Changes {
		if c.Alarming {
			d.Alarming++
		}
	}
	return d
}

func deltaStr(before, after int) string {
	switch {
	case after > before:
		return fmt.Sprintf("+%d", after-before)
	case after < before:
		return fmt.Sprintf("%d", after-before)
	}
	return "="
}

// ConsoleDiff renders a comparison to w.
func ConsoleDiff(w io.Writer, d Diff, color bool) {
	p := newPalette(color)

	fmt.Fprintf(w, "\n%s%s  ARGUS  scan comparison%s\n", p.bold, p.cyan, p.reset)
	fmt.Fprintf(w, "%s\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500%s\n", p.gray, p.reset)
	fmt.Fprintf(w, "Host      : %s\n", d.New.Host.Hostname)
	fmt.Fprintf(w, "Before    : %s\n", d.Old.FinishedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "After     : %s\n\n", d.New.FinishedAt.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "  HARDENING  %3d \u2192 %3d  (%s)\n",
		d.Old.Hardening.Score, d.New.Hardening.Score,
		deltaStr(d.Old.Hardening.Score, d.New.Hardening.Score))
	fmt.Fprintf(w, "  INTEGRITY  %3d \u2192 %3d  (%s)\n\n",
		d.Old.Integrity.Score, d.New.Integrity.Score,
		deltaStr(d.Old.Integrity.Score, d.New.Integrity.Score))

	if len(d.Changes) == 0 {
		fmt.Fprintf(w, "%s  Nothing changed between the two scans.%s\n", p.green, p.reset)
		return
	}

	sections := []struct {
		kind, label, colour string
	}{
		{KindNew, "NEW - problems that were not there before", p.red},
		{KindWorse, "WORSENED", p.red},
		{KindAppeared, "APPEARED - new entries in a watched inventory", p.yellow},
		{KindDisappeared, "GONE - entries that left a watched inventory", p.gray},
		{KindBetter, "IMPROVED", p.green},
		{KindResolved, "RESOLVED", p.green},
	}

	for _, s := range sections {
		var group []Change
		for _, c := range d.Changes {
			if c.Kind == s.kind {
				group = append(group, c)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s[%s]%s\n", p.bold+s.colour, s.label, p.reset)
		for _, c := range group {
			if c.Line != "" {
				fmt.Fprintf(w, "  %s%-14s%s %s\n", s.colour, c.ID, p.reset, c.Line)
				continue
			}
			fmt.Fprintf(w, "  %s%-5s%s %s  (%s)\n",
				s.colour, c.Severity.Abbrev(), p.reset, c.Title, c.ID)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s%d change(s), %d requiring attention.%s\n",
		p.gray, len(d.Changes), d.Alarming, p.reset)
	if d.Alarming > 0 {
		fmt.Fprintf(w, "%sA new listening port, autostart entry or SUID binary is how an intrusion first shows.%s\n",
			p.gray, p.reset)
	}
}
