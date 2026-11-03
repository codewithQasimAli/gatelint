package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl004 = register(&Rule{
	ID:        "GL004",
	Title:     "continue-on-error on a scanner step or job",
	Severity:  model.High,
	Platforms: "GitHub Actions",
	Explanation: `"continue-on-error: true" tells GitHub Actions to treat a failed step (or job) as a success. On ` +
		`a scanner step this keeps the workflow green whatever the scanner finds; the only trace is a warning ` +
		`annotation that is easy to miss. When the value is an expression such as ` +
		`"${{ matrix.experimental }}", gatelint reports it at medium severity as conditional, because the ` +
		`gate is only disabled for some runs.`,
	Hint: `remove continue-on-error, or move non-blocking experiments to a separate job`,
	Before: `- name: Semgrep
  run: semgrep ci
  continue-on-error: true`,
	After: `- name: Semgrep
  run: semgrep ci`,
})

// coeState classifies a continue-on-error value.
func coeState(v model.Value) (on, conditional bool) {
	if !v.Set {
		return false, false
	}
	raw := strings.TrimSpace(v.Raw)
	if v.IsExpression() {
		inner := strings.ToLower(exprInner(raw))
		switch inner {
		case "true":
			return true, false
		case "false":
			return false, false
		}
		return true, true
	}
	return strings.EqualFold(raw, "true"), false
}

// exprInner strips "${{ }}" from a GitHub expression.
func exprInner(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = strings.TrimSpace(s[3 : len(s)-2])
	}
	return s
}

func checkGL004(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if u.Pipeline.Platform != model.GitHub || u.Disabled || u.infoOnly() {
			continue
		}
		type src struct {
			v     model.Value
			scope string
		}
		var srcs []src
		if u.Step != nil {
			srcs = append(srcs, src{u.Step.ContinueOnError, "step"})
		}
		if u.Job != nil {
			srcs = append(srcs, src{u.Job.ContinueOnError, "job"})
		}
		for _, s := range srcs {
			on, cond := coeState(s.v)
			if !on {
				continue
			}
			sev := gl004.Severity
			msg := fmt.Sprintf("%s runs in a %s with continue-on-error: true, so a failing scan does not fail the workflow", u.Name(), s.scope)
			if cond {
				sev = model.Medium
				msg = fmt.Sprintf("%s runs in a %s with continue-on-error: %s, which disables the gate whenever the expression is true", u.Name(), s.scope, strings.TrimSpace(s.v.Raw))
			}
			f := gl004.finding(u, s.v.Pos, sev, msg)
			f.Conditional = cond
			out = append(out, f)
		}
	}
	return out
}

func init() { gl004.check = checkGL004 }
