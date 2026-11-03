package rules

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

// neutering lists the rules whose findings mean a scanner does not gate.
var neutering = map[string]bool{
	"GL001": true, "GL002": true, "GL003": true, "GL004": true,
	"GL005": true, "GL006": true, "GL007": true, "GL008": true,
}

var gateCmdRe = regexp.MustCompile(`\bexit\s+([1-9]|\$)|\bjq\s+(-\S+\s+)*-e\b|\bjq\s+-e|\bfalse\b|::error`)

// mitigation records why a neutered scanner looks report-only.
type mitigation struct {
	// low lowers findings to low severity; otherwise one level.
	low  bool
	note string
}

// mitigate lowers the severity of neutering findings for scanners that run
// only to produce a report while the build is gated elsewhere:
//
//   - the same scanner also runs in gating mode in the same job (GitHub) or
//     pipeline (GitLab);
//   - a later step in the same job reads the report and fails on it;
//   - the report is uploaded to code scanning (one level lower only).
func mitigate(ctx *Context, findings []model.Finding) {
	neutered := map[int]bool{}
	for _, f := range findings {
		if f.UseID >= 0 && neutering[f.RuleID] {
			neutered[f.UseID] = true
		}
	}
	notes := map[int]mitigation{}
	for _, u := range ctx.Uses {
		if !neutered[u.ID] || u.Tool == nil {
			continue
		}
		if g := gatingTwin(ctx, u, neutered); g != nil {
			notes[u.ID] = mitigation{true, fmt.Sprintf("%s also runs in gating mode at %s:%d, so this run looks report-only", u.Name(), g.Pos.File, g.Pos.Line)}
			continue
		}
		if e, out := laterGate(ctx, u); e != nil {
			notes[u.ID] = mitigation{true, fmt.Sprintf("a later command at %s:%d appears to fail the build based on %s", e.Pos.File, e.Pos.Line, out)}
			continue
		}
		if e := laterSarifUpload(ctx, u); e != nil {
			notes[u.ID] = mitigation{false, "results are uploaded to code scanning, which blocks merges only when code scanning merge protection is configured"}
			continue
		}
		if r := gitlabSecurityReport(u); r != "" {
			notes[u.ID] = mitigation{false, "results are published as the GitLab report artifact " + r + ", which blocks merges only through merge request approval policies"}
		}
	}
	for i := range findings {
		f := &findings[i]
		n, ok := notes[f.UseID]
		if !ok || f.UseID < 0 || !neutering[f.RuleID] || f.Severity == model.Info {
			continue
		}
		if n.low {
			f.Severity = model.Low
		} else {
			f.Severity = f.Severity.Lower()
		}
		f.Notes = append(f.Notes, n.note)
	}
	ctx.mitigations = map[int]string{}
	for id, n := range notes {
		ctx.mitigations[id] = n.note
	}
}

func gatingTwin(ctx *Context, u *Use, neutered map[int]bool) *Use {
	// Only a run that writes a report can be a report-only companion.
	if u.Eval == nil || len(u.Eval.Outputs) == 0 {
		return nil
	}
	for _, o := range ctx.Uses {
		if o == u || o.Pipeline != u.Pipeline || o.Tool != u.Tool || neutered[o.ID] || o.Disabled || o.Eval == nil {
			continue
		}
		// On GitHub only a gating run in the same job counts; separate
		// jobs often scan different targets.
		if u.Pipeline.Platform == model.GitHub && o.Job != u.Job {
			continue
		}
		if o.Eval.Gating() {
			return o
		}
	}
	return nil
}

func laterGate(ctx *Context, u *Use) (*Event, string) {
	if u.Eval == nil || len(u.Eval.Outputs) == 0 || u.Job == nil {
		return nil, ""
	}
	for _, out := range u.Eval.Outputs {
		base := path.Base(strings.Trim(out, `"'`))
		if base == "" || base == "." || base == "/" || base == "-" {
			continue
		}
		for _, job := range jobsAfter(ctx, u) {
			// Join the statements of each later step so a gate spread over
			// several lines ("n=$(jq ...)", "if [ $n -gt 0 ]; then exit 1")
			// is recognised.
			var first *Event
			var text strings.Builder
			flush := func() *Event {
				defer func() { first = nil; text.Reset() }()
				if first != nil && strings.Contains(text.String(), base) && gateCmdRe.MatchString(text.String()) {
					return first
				}
				return nil
			}
			for i := range ctx.Events[job] {
				e := &ctx.Events[job][i]
				if (job == u.Job && e.Order <= u.Order) || e.Uses != "" {
					continue
				}
				if first != nil && e.Group != first.Group {
					if g := flush(); g != nil {
						return g, base
					}
				}
				if first == nil {
					first = e
				}
				text.WriteString(e.Text)
				text.WriteString("\n")
			}
			if g := flush(); g != nil {
				return g, base
			}
		}
	}
	return nil, ""
}

// jobsAfter lists the jobs whose events may consume u's report: the same job
// on GitHub, any job of the pipeline on GitLab (artifacts pass reports
// between stages).
func jobsAfter(ctx *Context, u *Use) []*model.Job {
	if u.Pipeline.Platform == model.GitHub {
		return []*model.Job{u.Job}
	}
	return u.Pipeline.Jobs
}

// gitlabSecurityReport returns the security report artifact the use writes,
// if any.
func gitlabSecurityReport(u *Use) string {
	if u.Job == nil || u.Eval == nil || len(u.Job.SecurityReports) == 0 {
		return ""
	}
	for _, out := range u.Eval.Outputs {
		for _, r := range u.Job.SecurityReports {
			if path.Base(strings.Trim(out, `"'`)) == path.Base(r) {
				return r
			}
		}
	}
	return ""
}

func laterSarifUpload(ctx *Context, u *Use) *Event {
	if u.Job == nil || u.Pipeline.Platform != model.GitHub {
		return nil
	}
	for i := range ctx.Events[u.Job] {
		e := &ctx.Events[u.Job][i]
		if e.Order <= u.Order {
			continue
		}
		if strings.HasPrefix(strings.ToLower(e.Uses), "github/codeql-action/upload-sarif") {
			return e
		}
	}
	return nil
}
