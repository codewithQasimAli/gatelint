package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl008 = register(&Rule{
	ID:        "GL008",
	Title:     "Neutering input on a scanner action",
	Severity:  model.High,
	Platforms: "GitHub Actions",
	Explanation: `Scanner actions expose inputs that keep the step green whatever is found: ` +
		`aquasecurity/trivy-action with exit-code: '0', anchore/scan-action with fail-build: false, ` +
		`bridgecrewio/checkov-action and aquasecurity/tfsec-action with soft_fail: true, ` +
		`pypa/gh-action-pip-audit with internal-be-careful-allow-failure: true, and neutering flags passed through ` +
		`an args input (for example securego/gosec with args: -no-fail). These inputs are usually added to unblock ` +
		`a release and then forgotten.`,
	Hint: `remove the input (or set it to its gating value) so findings fail the step`,
	Before: `- uses: anchore/scan-action@v6
  with:
    image: myapp:latest
    fail-build: false`,
	After: `- uses: anchore/scan-action@v6
  with:
    image: myapp:latest
    severity-cutoff: high`,
})

func checkGL008(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if u.Kind != "action" || u.Eval == nil || u.Disabled || u.infoOnly() {
			continue
		}
		ref := strings.TrimSpace(u.Step.Uses.Raw)
		if i := strings.Index(ref, "@"); i >= 0 {
			ref = ref[:i]
		}
		for _, h := range u.Eval.Neuters {
			var pos model.Pos
			var msg string
			switch {
			case h.FromEnv:
				pos = u.Pos
				msg = fmt.Sprintf("%s runs with %s in its environment, which %s", ref, h.Label(), h.Desc)
			case h.Arg.Line > 0 || h.Arg.Value != "":
				pos = u.ArgsPos
				msg = fmt.Sprintf("%s input %s passes \"%s\", which %s", ref, u.Action.ArgsInput, h.Label(), h.Desc)
			default:
				pos = u.InputPos[strings.ToLower(h.Name)]
				msg = fmt.Sprintf("%s input \"%s: %s\" %s", ref, h.Name, h.Value, h.Desc)
			}
			out = append(out, gl008.finding(u, pos, gl008.Severity, msg))
		}
	}
	return out
}

func init() { gl008.check = checkGL008 }
