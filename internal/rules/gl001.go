package rules

import (
	"fmt"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl001 = register(&Rule{
	ID:        "GL001",
	Title:     "Scanner failure swallowed by the shell",
	Severity:  model.High,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `The scanner's exit status is discarded by the shell, so a failing scan can never fail the job. ` +
		`The usual culprit is "|| true", but "|| :", "|| exit 0", "|| echo ...", a leading "!", running the scanner ` +
		`inside $(...) as an argument of another command, running it in the background with "&", using it as an if ` +
		`condition without a failing branch, and putting it on the left of "&&" in the middle of a script (bash ` +
		`exempts that command from errexit) all have the same effect. The scanner still runs and prints findings, ` +
		`so the job looks protected while it is not. gatelint only reports this when the swallowed command is a ` +
		`known scanner.`,
	Hint: `remove the "|| true" (or equivalent) so a failing scan fails the job`,
	Before: `- name: Scan image
  run: trivy image --exit-code 1 myapp:latest || true`,
	After: `- name: Scan image
  run: trivy image --exit-code 1 myapp:latest`,
})

func checkGL001(ctx *Context) []model.Finding {
	var out []model.Finding
	for _, u := range ctx.Uses {
		if u.Inv == nil || u.Inv.Swallow == nil || u.Disabled || u.infoOnly() || u.Section == "after_script" {
			continue
		}
		sw := u.Inv.Swallow
		var msg, hint string
		switch sw.Kind {
		case "or":
			msg = fmt.Sprintf("%s failure is swallowed by `%s`", u.Name(), sw.Text)
		case "negated":
			msg = fmt.Sprintf("%s exit status is inverted with \"!\", which also exempts it from errexit", u.Name())
			hint = `remove the "!" in front of the scanner`
		case "and":
			msg = fmt.Sprintf("%s is on the left of `%s` in the middle of the script; bash exempts it from errexit, so a failing scan does not stop the job", u.Name(), sw.Text)
			hint = `run the scanner as its own command, or append "|| exit 1" to the list`
		case "if":
			msg = fmt.Sprintf("%s runs as an if/while condition and no branch exits with an error", u.Name())
			hint = `add "exit 1" to the branch that handles a failed scan`
		case "subst":
			msg = fmt.Sprintf("%s runs inside a command substitution whose status is discarded by `%s`", u.Name(), sw.Text)
			hint = `run the scanner directly and capture its output with --output instead of $(...)`
		case "background":
			msg = fmt.Sprintf("%s runs in the background with \"&\", so its exit status is never checked", u.Name())
			hint = `run the scanner in the foreground, or "wait" for it and check its status`
		default:
			msg = fmt.Sprintf("%s failure is swallowed by the shell", u.Name())
		}
		f := gl001.finding(u, u.Pos, gl001.Severity, msg)
		if hint != "" {
			f.Hint = hint
		}
		out = append(out, f)
	}
	return out
}

func init() { gl001.check = checkGL001 }
