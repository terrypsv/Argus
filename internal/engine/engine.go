// Package engine runs the registered checks, aggregates their findings and
// computes the final security score.
package engine

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"argus/internal/model"
)

// Version of the tool, surfaced in reports.
const Version = "0.1.0"

// Config holds runtime options that individual checks may read.
type Config struct {
	// ScanRoots limits filesystem walks (SUID, world-writable, ...). When empty
	// each check falls back to sensible OS defaults.
	ScanRoots []string
	// BaselinePath is where the file-integrity baseline is read from / written to.
	BaselinePath string
	// Quick skips the slower filesystem walks.
	Quick bool
	// Verbose enables extra informational findings.
	Verbose bool
}

// Context is passed to every check. It carries the config and a logger hook so
// checks stay decoupled from the CLI.
type Context struct {
	Config Config
	Host   model.HostInfo
	// Log is called for progress messages; it is safe to leave nil.
	Log func(format string, args ...any)
}

func (c *Context) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

// CheckFunc is the unit of work. It must never panic in normal operation, but
// the runner recovers panics defensively so a single broken check cannot abort
// the whole scan.
type CheckFunc func(ctx *Context) []model.Finding

// Check couples a stable name/category with its implementation.
type Check struct {
	Name     string
	Category string
	Fn       CheckFunc
}

// Runner executes a list of checks.
type Runner struct {
	checks []Check
	ctx    *Context
}

// New builds a Runner for the given checks and config.
func New(checks []Check, cfg Config) *Runner {
	host := gatherHost()
	return &Runner{
		checks: checks,
		ctx: &Context{
			Config: cfg,
			Host:   host,
			Log: func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, "  … "+format+"\n", args...)
			},
		},
	}
}

// Context exposes the runner's context (used by commands that need host info).
func (r *Runner) Context() *Context { return r.ctx }

// Run executes every check and returns a fully-populated Report.
func (r *Runner) Run() model.Report {
	start := time.Now()
	var findings []model.Finding

	for _, ch := range r.checks {
		r.ctx.logf("%s", ch.Name)
		findings = append(findings, r.runOne(ch)...)
	}

	rep := model.Report{
		Tool:       "Argus",
		Version:    Version,
		Host:       r.ctx.Host,
		StartedAt:  start,
		FinishedAt: time.Now(),
		Findings:   findings,
	}
	rep.DurationMS = rep.FinishedAt.Sub(rep.StartedAt).Milliseconds()
	total, counts := score(findings)
	rep.Score = total
	rep.Grade = grade(total)
	rep.Counts = counts

	sortFindings(rep.Findings)
	for i := range rep.Findings {
		rep.Findings[i].Normalise()
	}
	return rep
}

// runOne executes a single check, converting any panic into an error finding.
func (r *Runner) runOne(ch Check) (out []model.Finding) {
	defer func() {
		if rec := recover(); rec != nil {
			out = []model.Finding{{
				ID:       ch.Name + "-PANIC",
				Category: ch.Category,
				Title:    "Check crashed and was skipped",
				Severity: model.SevInfo,
				Passed:   false,
				Err:      fmt.Sprintf("panic: %v", rec),
			}}
		}
	}()
	res := ch.Fn(r.ctx)
	for i := range res {
		if res[i].Category == "" {
			res[i].Category = ch.Category
		}
	}
	return res
}

// score turns findings into a 0..100 value and a per-severity count of issues.
func score(findings []model.Finding) (int, map[string]int) {
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
		"passed": 0, "failed": 0, "errors": 0,
	}
	penalty := 0.0
	for _, f := range findings {
		if f.Err != "" {
			counts["errors"]++
		}
		if f.Passed {
			counts["passed"]++
			continue
		}
		// A non-info finding that did not pass is an issue.
		if f.Severity == model.SevInfo {
			continue
		}
		counts["failed"]++
		counts[f.Severity.String()]++
		penalty += f.Severity.Weight()
	}
	s := 100.0 - penalty
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return int(s + 0.5), counts
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score >= 40:
		return "E"
	default:
		return "F"
	}
}

// sortFindings orders failures first (highest severity), then passes.
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Passed != b.Passed {
			return !a.Passed // failures before passes
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.ID < b.ID
	})
}

func gatherHost() model.HostInfo {
	h, _ := os.Hostname()
	return model.HostInfo{
		Hostname: h,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		NumCPU:   runtime.NumCPU(),
		Kernel:   kernelString(),
		Platform: platformString(),
	}
}
