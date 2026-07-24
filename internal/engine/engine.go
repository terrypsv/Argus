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
//
// It is a var rather than a const so a release build can stamp the git tag into
// the binary with -ldflags "-X argus/internal/engine.Version=v1.2.3". A binary
// that cannot say which version it is makes a report impossible to reproduce.
var Version = "dev"

// Author and Repository identify who produced a report. An audit result that
// travels without saying which tool and which build produced it cannot be
// challenged or reproduced, which is half of what makes it worth anything.
var (
	Author     = "Terry PASSAVE"
	Repository = "github.com/terrypsv/Argus"
)

// Config holds runtime options that individual checks may read.
type Config struct {
	// ScanRoots limits filesystem walks (SUID, world-writable, ...). When empty
	// each check falls back to sensible OS defaults.
	ScanRoots []string
	// BaselinePath is where the file-integrity baseline is read from / written to.
	BaselinePath string
	// Quick skips the slower filesystem walks.
	Quick bool
	// ExceptionsPath points at the file of knowingly accepted findings.
	ExceptionsPath string
	// VerifyPackages enables comparison of every installed file against the
	// digests published by the distribution. Slow, but not vulnerable to the
	// trust-on-first-use weakness of a locally generated baseline.
	VerifyPackages bool
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
		Author:     Author,
		Repository: Repository,
		Host:       r.ctx.Host,
		StartedAt:  start,
		FinishedAt: time.Now(),
		Findings:   findings,
	}
	rep.DurationMS = rep.FinishedAt.Sub(rep.StartedAt).Milliseconds()

	// Accepted exceptions are neutralised before scoring, but stay in the report.
	ef, err := LoadExceptions(r.ctx.Config.ExceptionsPath)
	if err != nil {
		r.ctx.logf("exceptions: %v", err)
	}
	suppressed, expired := applyExceptions(rep.Findings, ef, time.Now())
	rep.Suppressed = suppressed
	for _, id := range expired {
		r.ctx.logf("exception for %s has expired and no longer applies", id)
	}

	rep.Hardening = axisScore(rep.Findings, model.AxisHardening)
	rep.Integrity = axisScore(rep.Findings, model.AxisIntegrity)
	rep.Score = rep.Hardening.Score
	if rep.Integrity.Score < rep.Score {
		rep.Score = rep.Integrity.Score
	}
	rep.Grade = grade(rep.Score)
	rep.Verdict = verdict(rep.Hardening, rep.Integrity)
	rep.Counts = countFindings(rep.Findings)
	rep.Weights = map[string]float64{}
	for _, sev := range []model.Severity{
		model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo,
	} {
		rep.Weights[sev.String()] = sev.Weight()
	}

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
// countFindings tallies severities. It never computes a score - that is the
// job of axisScore, so that counts and scoring cannot drift apart.
func countFindings(findings []model.Finding) map[string]int {
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
		"passed": 0, "failed": 0, "errors": 0, "accepted": 0,
	}
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
		// Accepted findings are real problems the operator chose to carry.
		// They are neither passed nor counted as open issues.
		if f.Accepted != "" {
			counts["accepted"]++
			continue
		}
		counts["failed"]++
		counts[f.Severity.String()]++
	}
	return counts
}

// axisScore computes the 0..100 score for one axis in isolation, together with
// the raw score that ignores every acceptance. Publishing both is what stops a
// waiver from quietly turning into a clean bill of health.
func axisScore(findings []model.Finding, axis model.Axis) model.AxisScore {
	penalty, rawPenalty := 0.0, 0.0
	issues, accepted := 0, 0
	for _, f := range findings {
		if f.Passed || f.Severity == model.SevInfo {
			continue
		}
		if model.AxisOf(f) != axis {
			continue
		}
		rawPenalty += f.Severity.Weight()
		if f.Accepted != "" {
			accepted++
			continue
		}
		issues++
		penalty += f.Severity.Weight()
	}
	clamp := func(p float64) int {
		s := 100.0 - p
		if s < 0 {
			s = 0
		}
		if s > 100 {
			s = 100
		}
		return int(s + 0.5)
	}
	v, raw := clamp(penalty), clamp(rawPenalty)
	return model.AxisScore{
		Score: v, Grade: grade(v),
		RawScore: raw, RawGrade: grade(raw),
		Issues: issues, Accepted: accepted,
	}
}

// verdict turns the two axes into one sentence a human can act on. Integrity
// dominates: a tampering indicator matters more than any amount of missing
// hardening, because it means the attack already happened.
func verdict(hard, integ model.AxisScore) string {
	var base string
	switch {
	case integ.Score < 60:
		base = "Compromise indicators found - investigate these before anything else"
	case integ.Issues > 0:
		base = "Possible tampering indicators - review the integrity findings"
	case hard.Score >= 90:
		base = "No compromise indicators; hardening is solid"
	case hard.Score >= 60:
		base = "No compromise indicators; hardening needs work"
	default:
		base = "No compromise indicators, but this host is barely hardened"
	}
	if n := hard.Accepted + integ.Accepted; n > 0 {
		base += fmt.Sprintf(" - %d accepted finding(s) excluded from the score", n)
	}
	return base
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
