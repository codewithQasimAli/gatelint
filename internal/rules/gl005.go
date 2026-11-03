package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl005 = register(&Rule{
	ID:        "GL005",
	Title:     "Scanner job allowed to fail",
	Severity:  model.High,
	Platforms: "GitLab CI",
	Explanation: `"allow_failure: true" lets a GitLab job fail without failing the pipeline; the merge request ` +
		`shows a warning icon and can still be merged. "allow_failure: exit_codes" does the same for specific exit ` +
		`codes, and when those include the scanner's failure code (1 for most tools, 2 for Grype with --fail-on, ` +
		`183 for TruffleHog, or the value given to --exit-code) the scan can never block the pipeline. The same ` +
		`applies to an allow_failure inside rules: when it covers every rule that runs the job (reported as ` +
		`conditional when only some rules set it), and to scanners placed in after_script, whose exit status ` +
		`GitLab ignores.`,
	Hint: `remove allow_failure from the scanner job (or drop the scanner's failure code from exit_codes)`,
	Before: `trivy:
  stage: test
  script:
    - trivy fs --exit-code 1 .
  allow_failure: true`,
	After: `trivy:
  stage: test
  script:
    - trivy fs --exit-code 1 .`,
})

func intersects(a, b []int) []int {
	var out []int
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
			}
		}
	}
	return out
}

func checkGL005(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if u.Pipeline.Platform != model.GitLab || u.Job == nil || u.Disabled || u.infoOnly() {
			continue
		}
		if u.Section == "after_script" {
			f := gl005.finding(u, u.Pos, gl005.Severity, fmt.Sprintf("%s runs in after_script; GitLab ignores the exit status of after_script, so the scan can never fail the job", u.Name()))
			f.Hint = "move the scanner from after_script to script"
			out = append(out, f)
			continue
		}
		if f, ok := allowFailureFinding(u, u.Job.AllowFailure, false); ok {
			out = append(out, f)
		}
		var runnable, allowing []model.RuleEntry
		for _, r := range u.Job.Rules {
			if strings.EqualFold(strings.TrimSpace(r.When.Raw), "never") {
				continue
			}
			runnable = append(runnable, r)
			if allows(u, r.AllowFailure) {
				allowing = append(allowing, r)
			}
		}
		if len(allowing) > 0 {
			cond := len(allowing) < len(runnable)
			f, _ := allowFailureFinding(u, allowing[0].AllowFailure, true)
			if cond {
				f.Severity = model.Medium
				f.Conditional = true
				f.Message = fmt.Sprintf("%s job sets allow_failure in %d of %d rules, so the scan cannot fail the pipeline when those rules match", u.Name(), len(allowing), len(runnable))
			}
			out = append(out, f)
		}
	}
	return out
}

func allows(u *Use, af model.AllowFailure) bool {
	if !af.Set {
		return false
	}
	if af.Bool {
		return true
	}
	return len(intersects(af.ExitCodes, u.Eval.FailCodes)) > 0
}

func allowFailureFinding(u *Use, af model.AllowFailure, inRules bool) (model.Finding, bool) {
	if !allows(u, af) {
		return model.Finding{}, false
	}
	where := "job"
	if inRules {
		where = "rule"
	}
	msg := fmt.Sprintf("%s %s has allow_failure: true, so a failing scan does not fail the pipeline", u.Name(), where)
	if !af.Bool {
		codes := intersects(af.ExitCodes, u.Eval.FailCodes)
		msg = fmt.Sprintf("%s %s allows exit code %s, which is the scanner's failure code, so findings never fail the pipeline", u.Name(), where, joinInts(codes))
	}
	return gl005.finding(u, af.Pos, gl005.Severity, msg), true
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

func init() { gl005.check = checkGL005 }
