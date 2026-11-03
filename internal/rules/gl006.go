package rules

import (
	"fmt"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl006 = register(&Rule{
	ID:        "GL006",
	Title:     "Neutering flag on the scanner command line",
	Severity:  model.High,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `Many scanners have a flag that keeps the exit code at 0 whatever they find: Bandit's ` +
		`--exit-zero, Checkov's and tfsec's --soft-fail, gosec's -no-fail, "--exit-code 0" for Trivy and Gitleaks, ` +
		`"npm audit --audit-level=none". The same applies to the equivalent environment variables, such as ` +
		`TRIVY_EXIT_CODE=0. The flag is often added "temporarily" to get a pipeline green and never removed. ` +
		`gatelint knows each scanner's flags from its catalog, which can be extended in .gatelint.yml.`,
	Hint: `remove the flag so the scanner exits non-zero on findings`,
	Before: `script:
  - bandit -r src --exit-zero`,
	After: `script:
  - bandit -r src`,
})

func checkGL006(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if u.Kind != "cli" || u.Eval == nil || u.Disabled || u.infoOnly() {
			continue
		}
		for _, h := range u.Eval.Neuters {
			pos := u.Pos
			msg := fmt.Sprintf("%s is run with \"%s\", which %s", u.Name(), h.Label(), h.Desc)
			if h.FromEnv {
				msg = fmt.Sprintf("%s runs with %s in its environment, which %s", u.Name(), h.Label(), h.Desc)
			} else if h.Arg.Line > 0 {
				pos = model.Pos{File: u.Pos.File, Line: h.Arg.Line, Column: h.Arg.Column}
			}
			out = append(out, gl006.finding(u, pos, gl006.Severity, msg))
		}
	}
	return out
}

func init() { gl006.check = checkGL006 }
