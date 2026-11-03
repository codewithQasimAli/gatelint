// Package model defines the platform-neutral representation of CI pipelines
// that the parsers produce and the rules consume, plus the finding and
// coverage types shared by the reporting layer.
package model

import (
	"fmt"
	"strings"
)

// Platform identifies the CI system a pipeline file belongs to.
type Platform string

// Supported platforms.
const (
	GitHub Platform = "github"
	GitLab Platform = "gitlab"
)

// Pos is a position in a source file. Line and Column are 1-based.
type Pos struct {
	File   string
	Line   int
	Column int
}

// IsZero reports whether the position is unset.
func (p Pos) IsZero() bool { return p.Line == 0 }

// String renders the position as file:line:column.
func (p Pos) String() string {
	if p.Column > 0 {
		return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Column)
	}
	return fmt.Sprintf("%s:%d", p.File, p.Line)
}

// Value is a scalar setting read from YAML together with its position.
type Value struct {
	Raw string
	Set bool
	Pos Pos
}

// IsExpression reports whether the value contains a GitHub expression.
func (v Value) IsExpression() bool { return strings.Contains(v.Raw, "${{") }

// Segment is a contiguous piece of shell script taken from one YAML scalar.
// Pos is the position of the first character of Text. ContColumn is the
// column at which continuation lines start (block scalars strip their
// indentation, so the column must be added back when reporting).
type Segment struct {
	Text       string
	Pos        Pos
	ContColumn int
}

// Script is a sequence of shell segments that run in one shell process.
type Script struct {
	// Section is "run" for GitHub, or before_script/script/after_script.
	Section  string
	Segments []Segment
}

// Input is one entry of a GitHub step's "with:" mapping.
type Input struct {
	Name  string
	Value Value
}

// Step is a GitHub Actions step.
type Step struct {
	Index           int
	Name            string
	Pos             Pos
	Uses            Value
	With            []Input
	Run             *Script
	Shell           Value
	If              Value
	ContinueOnError Value
	Env             map[string]Value
}

// Input returns the named "with:" input and whether it was set.
func (s *Step) Input(name string) (Value, bool) {
	for _, in := range s.With {
		if strings.EqualFold(in.Name, name) {
			return in.Value, true
		}
	}
	return Value{}, false
}

// AllowFailure models GitLab's allow_failure keyword.
type AllowFailure struct {
	Set       bool
	Bool      bool
	ExitCodes []int
	Pos       Pos
	Raw       string
}

// RuleEntry is one entry of a GitLab job's rules: list.
type RuleEntry struct {
	Pos          Pos
	If           string
	When         Value
	AllowFailure AllowFailure
}

// Job is a GitHub job, a composite action, or a GitLab job.
type Job struct {
	ID   string
	Name string
	Pos  Pos

	// GitHub
	Steps           []*Step
	If              Value
	ContinueOnError Value
	RunsOn          string
	Uses            Value
	DefaultShell    Value

	// GitLab
	Scripts      []*Script
	AllowFailure AllowFailure
	When         Value
	Rules        []RuleEntry
	Image        string
	// SecurityReports lists files published as GitLab security or code
	// quality report artifacts (artifacts:reports:sast and similar).
	SecurityReports []string
	// Template is the ID of the GitLab security template this job
	// overrides, when the job has no script of its own.
	Template string

	// Env holds job-level env (GitHub) or variables (GitLab).
	Env map[string]Value
}

// TemplateUse records a GitLab CI template or component that is included.
type TemplateUse struct {
	Name string
	Pos  Pos
}

// Note is an informational message about something the parser could not
// fully resolve.
type Note struct {
	Pos     Pos    `json:"-"`
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

// Pipeline is one parsed CI configuration file (plus, for GitLab, its local
// includes).
type Pipeline struct {
	File     string
	Platform Platform
	// Kind is "workflow", "composite-action" or "gitlab-ci".
	Kind      string
	Jobs      []*Job
	Env       map[string]Value
	Templates []TemplateUse
	Notes     []Note
	// Files lists every source file that contributed to the pipeline.
	Files []string
	// LocalRefs lists repository-relative paths of local reusable
	// workflows and actions referenced by this pipeline.
	LocalRefs []string
	// Root is the repository root directory the file belongs to.
	Root string
}

// AddNote appends a note at the given position.
func (p *Pipeline) AddNote(pos Pos, format string, args ...any) {
	if pos.File == "" {
		pos.File = p.File
	}
	p.Notes = append(p.Notes, Note{Pos: pos, File: pos.File, Line: pos.Line, Message: fmt.Sprintf(format, args...)})
}
