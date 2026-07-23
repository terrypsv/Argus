// Package model defines the core data structures shared across Argus:
// findings produced by checks, severity levels, and the final report.
package model

import "time"

// Severity ranks how serious a failed finding is.
type Severity int

const (
	SevInfo Severity = iota // purely informational, never penalises the score
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// String returns the upper-case label used in reports.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Weight is the number of points a single failed finding of this severity
// removes from the base score of 100.
func (s Severity) Weight() float64 {
	switch s {
	case SevCritical:
		return 35
	case SevHigh:
		return 18
	case SevMedium:
		return 7
	case SevLow:
		return 2
	default:
		return 0
	}
}

// SeverityFromString parses a label back into a Severity (used by config /
// baseline files). Unknown values map to SevInfo.
func SeverityFromString(s string) Severity {
	switch s {
	case "CRITICAL":
		return SevCritical
	case "HIGH":
		return SevHigh
	case "MEDIUM":
		return SevMedium
	case "LOW":
		return SevLow
	default:
		return SevInfo
	}
}

// Finding is the atomic result unit. A check emits zero or more of these.
// Passed == true  -> the control is satisfied (good).
// Passed == false -> a problem was found; Severity drives the score penalty.
type Finding struct {
	ID          string   `json:"id"`                    // stable identifier, e.g. "LNX-SSH-ROOT"
	Category    string   `json:"category"`              // grouping, e.g. "kernel", "disk", "network"
	Title       string   `json:"title"`                 // one-line human summary
	Severity    Severity `json:"-"`                     // numeric severity
	SeverityStr string   `json:"severity"`              // serialised label (set by Normalise)
	Passed      bool     `json:"passed"`                // true = secure, false = issue
	Detail      string   `json:"detail,omitempty"`      // what was observed
	Remediation string   `json:"remediation,omitempty"` // how to fix it
	Evidence    []string `json:"evidence,omitempty"`    // raw supporting lines (paths, config, etc.)
	Err         string   `json:"error,omitempty"`       // set if the check could not run reliably
}

// Normalise fills serialisation-only fields. Call before marshalling.
func (f *Finding) Normalise() {
	f.SeverityStr = f.Severity.String()
}

// HostInfo captures the environment the scan ran in.
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`       // runtime.GOOS
	Arch     string `json:"arch"`     // runtime.GOARCH
	Kernel   string `json:"kernel"`   // uname / os version string
	Platform string `json:"platform"` // friendly OS name + version when available
	NumCPU   int    `json:"num_cpu"`
}

// Report is the full output of a scan.
type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Host       HostInfo       `json:"host"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	DurationMS int64          `json:"duration_ms"`
	Score      int            `json:"score"` // 0..100
	Grade      string         `json:"grade"` // A..F
	Counts     map[string]int `json:"counts"`
	Findings   []Finding      `json:"findings"`
}
