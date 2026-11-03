package rules

import (
	"fmt"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl002 = register(&Rule{
	ID:        "GL002",
	Title:     "errexit disabled before a scanner",
	Severity:  model.High,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `"set +e" (or a custom shell started without -e, such as "shell: bash {0}") turns off errexit, so ` +
		`the script keeps going after a command fails. When a scanner runs while errexit is off and it is not the ` +
		`last command of the script, its failure is lost: the step's exit status is that of whatever runs last. ` +
		`gatelint does not report the pattern when the next command reads $? (for example "rc=$?") or when the ` +
		`scanner is the final command, because then the status still reaches the runner.`,
	Hint: `remove "set +e", or capture the status with rc=$? and exit with it`,
	Before: `- name: Scan
  run: |
    set +e
    gitleaks detect --source .
    echo "scan finished"`,
	After: `- name: Scan
  run: |
    gitleaks detect --source .
    echo "scan finished"`,
})

// gl002Applies reports whether GL002 fires for a use.
func gl002Applies(u *Use) bool {
	inv := u.Inv
	return inv != nil && inv.ErrexitOff && !inv.Last && !inv.StatusChecked && inv.Swallow == nil &&
		!u.Disabled && !u.infoOnly() && u.Section != "after_script"
}

func checkGL002(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if !gl002Applies(u) {
			continue
		}
		reason := u.Inv.ErrexitReason
		if u.Inv.ErrexitLine > 0 {
			reason += fmt.Sprintf(" on line %d", u.Inv.ErrexitLine)
		}
		if strings.HasPrefix(reason, "\"set ") {
			reason += " disables it"
		}
		msg := fmt.Sprintf("%s runs while errexit is off (%s) and is not the last command, so a failing scan does not fail the job", u.Name(), reason)
		out = append(out, gl002.finding(u, u.Pos, gl002.Severity, msg))
	}
	return out
}

func init() { gl002.check = checkGL002 }
