package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl007 = register(&Rule{
	ID:        "GL007",
	Title:     "Scanner does not gate by default",
	Severity:  model.Medium,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `Some scanners report findings but exit 0 unless asked to fail: Trivy needs --exit-code 1, Grype ` +
		`needs --fail-on, "semgrep scan" needs --error, TruffleHog needs --fail, and aquasecurity/trivy-action ` +
		`needs exit-code set to a non-zero value. Without the gating option the scan is informational only, which ` +
		`is easy to miss because the job log is full of findings. "snyk monitor" never fails on vulnerabilities and ` +
		`is reported at info severity; use "snyk test" to gate. When the gating option comes from a configuration ` +
		`file or an expression gatelint cannot evaluate, the scanner is listed as "unknown" in the coverage ` +
		`summary instead.`,
	Hint: `add the scanner's gating option so findings fail the build`,
	Before: `- name: Trivy
  uses: aquasecurity/trivy-action@0.28.0
  with:
    scan-type: fs`,
	After: `- name: Trivy
  uses: aquasecurity/trivy-action@0.28.0
  with:
    scan-type: fs
    exit-code: '1'`,
})

func checkGL007(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		e := u.Eval
		if e == nil || u.Disabled || e.InfoOnly || len(e.Neuters) > 0 || e.Gating() || e.Indeterminate() {
			continue
		}
		var f model.Finding
		if e.NeverGates {
			note := e.Note
			if note == "" {
				note = "this command never fails on findings"
			}
			f = gl007.finding(u, u.Pos, model.Info, fmt.Sprintf("%s: %s", u.Name(), note))
			f.Hint = "add a separate command that fails on findings (for Snyk, \"snyk test\")"
			out = append(out, f)
			continue
		}
		example := u.Tool.GateExample(e.Mode, u.Action)
		subject := u.Name()
		if u.Kind == "action" {
			subject = strings.TrimSpace(u.Step.Uses.Raw)
		}
		msg := fmt.Sprintf("%s exits 0 when it finds issues and no gating option is set", subject)
		f = gl007.finding(u, u.Pos, gl007.Severity, msg)
		if example != "" {
			if u.Kind == "action" && u.Action.ArgsInput == "" {
				f.Hint = fmt.Sprintf("set %s on the step so findings fail the build", example)
			} else {
				f.Hint = fmt.Sprintf("add %s so findings fail the build", example)
			}
		}
		out = append(out, f)
	}
	return out
}

func init() { gl007.check = checkGL007 }
