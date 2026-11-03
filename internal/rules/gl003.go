package rules

import (
	"fmt"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl003 = register(&Rule{
	ID:        "GL003",
	Title:     "Scanner piped without pipefail",
	Severity:  model.Medium,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `Without pipefail, a pipeline's exit status is that of its last command. "trivy image app | tee ` +
		`report.txt" therefore succeeds whenever tee succeeds, whatever Trivy found. On GitHub Actions the default ` +
		`shell for Linux and macOS runners when "shell:" is omitted is "bash -e {0}", which does not set pipefail; ` +
		`"shell: bash" runs "bash --noprofile --norc -eo pipefail {0}" and does. "shell: sh" runs "sh -e {0}" ` +
		`without pipefail. GitLab Runner enables pipefail where the shell supports it, so on GitLab this rule ` +
		`only fires after an explicit "set +o pipefail".`,
	Hint: `set "shell: bash" on the step (it adds -o pipefail) or add "set -o pipefail" before the pipeline`,
	Before: `- name: Scan
  run: trivy fs --exit-code 1 . | tee trivy.txt`,
	After: `- name: Scan
  shell: bash
  run: trivy fs --exit-code 1 . | tee trivy.txt`,
})

func checkGL003(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		inv := u.Inv
		if inv == nil || inv.PipedInto == "" || inv.Pipefail || inv.Swallow != nil || u.Disabled || u.infoOnly() ||
			u.Section == "after_script" || gl002Applies(u) {
			continue
		}
		msg := fmt.Sprintf("%s output is piped into \"%s\" and the shell does not set pipefail, so the step's status is that of \"%s\"", u.Name(), inv.PipedInto, inv.PipedInto)
		f := gl003.finding(u, u.Pos, gl003.Severity, msg)
		if u.Pipeline.Platform == model.GitLab {
			f.Hint = `remove "set +o pipefail" (GitLab Runner enables pipefail by default) or add "set -o pipefail" before the pipeline`
		}
		out = append(out, f)
	}
	return out
}

func init() { gl003.check = checkGL003 }
