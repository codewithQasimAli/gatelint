package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl009 = register(&Rule{
	ID:        "GL009",
	Title:     "Scanner disabled",
	Severity:  model.High,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `The scanner is configured but never runs automatically, so it cannot gate anything. On GitHub ` +
		`Actions this is "if: false" or "if: ${{ false }}" on the step or job. On GitLab CI it is "when: never", ` +
		`"when: manual" (a manual job does not run unless someone starts it, and is allowed to fail by default), ` +
		`rules: that always resolve to never or manual, or a security template disabled with SAST_DISABLED, ` +
		`SECRET_DETECTION_DISABLED, DEPENDENCY_SCANNING_DISABLED, CONTAINER_SCANNING_DISABLED or DAST_DISABLED ` +
		`set to "true". Other rules stay quiet for disabled scanners, since the scanner does not run at all.`,
	Hint: `remove the condition that disables the scanner`,
	Before: `include:
  - template: Jobs/Secret-Detection.gitlab-ci.yml
variables:
  SECRET_DETECTION_DISABLED: "true"`,
	After: `include:
  - template: Jobs/Secret-Detection.gitlab-ci.yml`,
})

// disabledReason is why a use never runs automatically.
type disabledReason struct {
	pos model.Pos
	msg string
}

// isFalseExpr reports whether a GitHub "if:" value is literally false.
func isFalseExpr(v model.Value) bool {
	if !v.Set {
		return false
	}
	s := strings.ToLower(exprInner(v.Raw))
	s = strings.Trim(s, "() ")
	return s == "false" || strings.HasPrefix(s, "false &&") || strings.HasPrefix(s, "false&&")
}

func isTrueValue(s string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(s), `"'`)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// markDisabled flags uses that never run, before the other rules run.
func markDisabled(ctx *Context) map[int][]disabledReason {
	out := map[int][]disabledReason{}
	for _, u := range ctx.Uses {
		var reasons []disabledReason
		switch u.Pipeline.Platform {
		case model.GitHub:
			if u.Step != nil && isFalseExpr(u.Step.If) {
				reasons = append(reasons, disabledReason{u.Step.If.Pos, fmt.Sprintf("%s step has if: %s and never runs", u.Name(), strings.TrimSpace(u.Step.If.Raw))})
			}
			if u.Job != nil && isFalseExpr(u.Job.If) {
				reasons = append(reasons, disabledReason{u.Job.If.Pos, fmt.Sprintf("%s runs in job %q, which has if: %s and never runs", u.Name(), u.Job.ID, strings.TrimSpace(u.Job.If.Raw))})
			}
		case model.GitLab:
			reasons = append(reasons, gitlabDisabled(u)...)
		}
		if len(reasons) > 0 {
			u.Disabled = true
			out[u.ID] = reasons
		}
	}
	return out
}

func gitlabDisabled(u *Use) []disabledReason {
	var reasons []disabledReason
	if u.Template != nil {
		for _, name := range u.Template.DisableVariables {
			for _, env := range []map[string]model.Value{u.Pipeline.Env, jobEnv(u)} {
				if v, ok := env[name]; ok && isTrueValue(v.Raw) {
					reasons = append(reasons, disabledReason{v.Pos, fmt.Sprintf("%s is disabled by %s: %q", u.Name(), name, v.Raw)})
				}
			}
		}
	}
	if u.Job == nil {
		return reasons
	}
	when := strings.ToLower(strings.TrimSpace(u.Job.When.Raw))
	switch when {
	case "never":
		reasons = append(reasons, disabledReason{u.Job.When.Pos, fmt.Sprintf("%s job has when: never and never runs", u.Name())})
	case "manual":
		reasons = append(reasons, disabledReason{u.Job.When.Pos, fmt.Sprintf("%s job has when: manual, so it only runs when started by hand and is allowed to fail", u.Name())})
	}
	if len(u.Job.Rules) > 0 {
		never, manual := 0, 0
		for _, r := range u.Job.Rules {
			switch strings.ToLower(strings.TrimSpace(r.When.Raw)) {
			case "never":
				never++
			case "manual":
				manual++
			}
		}
		pos := u.Job.Rules[0].Pos
		switch {
		case never == len(u.Job.Rules):
			reasons = append(reasons, disabledReason{pos, fmt.Sprintf("every rule of the %s job resolves to when: never, so the job never runs", u.Name())})
		case never+manual == len(u.Job.Rules):
			reasons = append(reasons, disabledReason{pos, fmt.Sprintf("every rule of the %s job that runs it is when: manual, so it never runs automatically", u.Name())})
		}
	}
	return reasons
}

func jobEnv(u *Use) map[string]model.Value {
	if u.Job == nil {
		return nil
	}
	// Only job-level variables that are not inherited copies of globals.
	out := map[string]model.Value{}
	for k, v := range u.Job.Env {
		if g, ok := u.Pipeline.Env[k]; ok && g.Pos == v.Pos {
			continue
		}
		out[k] = v
	}
	return out
}

func checkGL009(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		for _, r := range ctx.disabled[u.ID] {
			out = append(out, gl009.finding(u, r.pos, gl009.Severity, r.msg))
		}
	}
	return out
}

func init() { gl009.check = checkGL009 }
