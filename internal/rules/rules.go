// Package rules implements gatelint's detection rules. Each rule lives in its
// own file (gl001.go ... gl010.go) and inspects the scanner uses collected
// from the parsed pipelines.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/shell"
	"github.com/codewithQasimAli/gatelint/internal/suppress"
)

// Rule describes one check.
type Rule struct {
	ID          string
	Title       string
	Severity    model.Severity
	Platforms   string
	Explanation string
	// Hint is the one-line fix shown under each finding.
	Hint   string
	Before string
	After  string
	check  func(*Context) []model.Finding
}

// HelpURI returns the documentation link for the rule.
func (r *Rule) HelpURI() string {
	return "https://github.com/codewithQasimAli/gatelint/blob/main/docs/rules/" + r.ID + ".md"
}

var registry []*Rule

func register(r *Rule) *Rule {
	registry = append(registry, r)
	return r
}

// All returns every rule sorted by ID.
func All() []*Rule {
	out := append([]*Rule{}, registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ByID returns the rule with the given ID, or nil.
func ByID(id string) *Rule {
	for _, r := range registry {
		if strings.EqualFold(r.ID, id) {
			return r
		}
	}
	return nil
}

// Use is one scanner invocation found in a pipeline.
type Use struct {
	ID       int
	Tool     *catalog.Tool
	Template *catalog.GitLabTemplate
	// Kind is "cli", "action" or "template".
	Kind     string
	Pipeline *model.Pipeline
	Job      *model.Job
	Step     *model.Step
	Section  string
	Pos      model.Pos
	Inv      *shell.Invocation
	Eval     *catalog.Eval
	Action   *catalog.Action
	// InputPos maps action input names to their positions.
	InputPos map[string]model.Pos
	// ArgsPos is the position of the input holding CLI arguments, or of
	// the command for CLI uses.
	ArgsPos    model.Pos
	Order      int
	Confidence model.Confidence
	// Disabled is set by GL009 so other rules can stay quiet.
	Disabled bool
}

// Name returns the scanner's display name.
func (u *Use) Name() string {
	if u.Template != nil {
		return u.Template.Name
	}
	return u.Tool.Name
}

// JobName returns the job label for reports.
func (u *Use) JobName() string {
	if u.Job == nil {
		return ""
	}
	return u.Job.Name
}

// StepName returns the step label for reports.
func (u *Use) StepName() string {
	if u.Step == nil {
		if u.Section != "" && u.Section != "script" {
			return u.Section
		}
		return ""
	}
	return u.Step.Name
}

// infoOnly reports whether the scanner never gates by design.
func (u *Use) infoOnly() bool {
	if u.Template != nil {
		return true
	}
	return u.Eval != nil && (u.Eval.InfoOnly || u.Eval.NeverGates)
}

// Event is a step or shell statement in a job, in execution order. It is
// used to find later steps that consume a scanner's report.
type Event struct {
	Order int
	// Group identifies the step (GitHub) or script block (GitLab) the
	// event belongs to.
	Group  int
	Text   string
	Uses   string
	Inputs map[string]string
	Pos    model.Pos
}

// Context is the input to every rule.
type Context struct {
	Catalog    *catalog.Catalog
	Pipelines  []*model.Pipeline
	Uses       []*Use
	Events     map[*model.Job][]Event
	Directives map[string][]suppress.Directive
	// Disabled lists rule IDs turned off by configuration.
	Disabled map[string]bool

	disabled    map[int][]disabledReason
	mitigations map[int]string
}

// Run collects scanner uses from the pipelines and runs every enabled rule.
// It returns findings (not yet suppressed) and the uses for coverage.
func Run(ctx *Context) []model.Finding {
	var out []model.Finding
	ctx.disabled = markDisabled(ctx)
	for _, r := range All() {
		if ctx.Disabled[r.ID] {
			continue
		}
		out = append(out, r.check(ctx)...)
	}
	mitigate(ctx, out)
	sortFindings(out)
	assignFingerprints(out)
	return out
}

func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Tool < b.Tool
	})
}

// assignFingerprints gives each finding a stable identifier that does not
// depend on line numbers, so it survives unrelated edits.
func assignFingerprints(fs []model.Finding) {
	seen := map[string]int{}
	for i := range fs {
		f := &fs[i]
		key := strings.Join([]string{f.RuleID, f.File, f.Job, f.Step, f.Tool}, "\x00")
		n := seen[key]
		seen[key] = n + 1
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", key, n)))
		f.Fingerprint = hex.EncodeToString(sum[:16])
	}
}

// finding builds a finding for a use.
func (r *Rule) finding(u *Use, pos model.Pos, sev model.Severity, msg string) model.Finding {
	if pos.IsZero() {
		pos = u.Pos
	}
	if pos.File == "" {
		pos.File = u.Pos.File
	}
	conf := u.Confidence
	if conf == "" {
		conf = model.ConfidenceHigh
	}
	return model.Finding{
		RuleID:     r.ID,
		Title:      r.Title,
		Severity:   sev,
		Confidence: conf,
		File:       pos.File,
		Line:       pos.Line,
		Column:     pos.Column,
		Job:        u.JobName(),
		Step:       u.StepName(),
		Tool:       u.Name(),
		Message:    msg,
		Hint:       r.Hint,
		UseID:      u.ID,
	}
}
