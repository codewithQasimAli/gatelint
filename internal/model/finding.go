package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity orders findings by impact.
type Severity int

// Severity levels, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
)

var severityNames = []string{"info", "low", "medium", "high"}

// String returns the lower-case name of the severity.
func (s Severity) String() string {
	if s < Info || s > High {
		return "unknown"
	}
	return severityNames[s]
}

// Upper returns the upper-case name of the severity.
func (s Severity) Upper() string { return strings.ToUpper(s.String()) }

// ParseSeverity converts a name to a Severity.
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(n, name) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q", name)
}

// MarshalJSON encodes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON decodes a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Lower returns the next lower severity, never going below Low.
func (s Severity) Lower() Severity {
	if s > Low {
		return s - 1
	}
	return s
}

// Confidence describes how certain a finding is.
type Confidence string

// Confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
)

// Finding is one reported problem.
type Finding struct {
	RuleID            string     `json:"ruleId"`
	Title             string     `json:"title"`
	Severity          Severity   `json:"severity"`
	Confidence        Confidence `json:"confidence"`
	Conditional       bool       `json:"conditional,omitempty"`
	File              string     `json:"file"`
	Line              int        `json:"line"`
	Column            int        `json:"column,omitempty"`
	Job               string     `json:"job,omitempty"`
	Step              string     `json:"step,omitempty"`
	Tool              string     `json:"scanner,omitempty"`
	Message           string     `json:"message"`
	Hint              string     `json:"fix"`
	Notes             []string   `json:"notes,omitempty"`
	Suppressed        bool       `json:"suppressed"`
	SuppressionReason string     `json:"suppressionReason,omitempty"`
	Fingerprint       string     `json:"fingerprint"`

	// UseID links the finding to the scanner use it was raised for, so
	// coverage can be computed. It is -1 for findings not tied to a use.
	UseID int `json:"-"`
}

// Location renders file:line for display.
func (f Finding) Location() string {
	return fmt.Sprintf("%s:%d", f.File, f.Line)
}

// Where renders the job/step label for display.
func (f Finding) Where() string {
	switch {
	case f.Job != "" && f.Step != "":
		return f.Job + " / " + f.Step
	case f.Job != "":
		return f.Job
	default:
		return f.Step
	}
}

// GateStatus classifies a scanner invocation.
type GateStatus string

// Gate statuses.
const (
	StatusGating    GateStatus = "gating"
	StatusNeutered  GateStatus = "neutered"
	StatusNonGating GateStatus = "non-gating"
	StatusDisabled  GateStatus = "disabled"
	StatusUnknown   GateStatus = "unknown"
)

// CoverageEntry is one scanner invocation in the coverage summary.
type CoverageEntry struct {
	Scanner string     `json:"scanner"`
	Job     string     `json:"job,omitempty"`
	Step    string     `json:"step,omitempty"`
	Line    int        `json:"line"`
	Status  GateStatus `json:"status"`
	Rules   []string   `json:"rules,omitempty"`
	Note    string     `json:"note,omitempty"`
}

// FileCoverage groups coverage entries by file.
type FileCoverage struct {
	File     string          `json:"file"`
	Platform Platform        `json:"platform"`
	Scanners []CoverageEntry `json:"scanners"`
}

// FileError is a file that could not be read or parsed.
type FileError struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

// Error implements error.
func (e FileError) Error() string { return e.File + ": " + e.Message }

// Result is the outcome of a scan.
type Result struct {
	Files    []string       `json:"files"`
	Findings []Finding      `json:"findings"`
	Coverage []FileCoverage `json:"coverage"`
	Notes    []Note         `json:"notes"`
	Errors   []FileError    `json:"errors"`
}

// Counts returns the number of unsuppressed findings per severity and the
// number of suppressed findings.
func (r *Result) Counts() (bySeverity map[Severity]int, suppressed int) {
	bySeverity = map[Severity]int{}
	for _, f := range r.Findings {
		if f.Suppressed {
			suppressed++
			continue
		}
		bySeverity[f.Severity]++
	}
	return bySeverity, suppressed
}

// FailsAt reports whether any unsuppressed finding is at or above min.
func (r *Result) FailsAt(min Severity) bool {
	for _, f := range r.Findings {
		if !f.Suppressed && f.Severity >= min {
			return true
		}
	}
	return false
}
