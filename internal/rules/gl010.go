package rules

import (
	"fmt"
	"sort"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

var gl010 = register(&Rule{
	ID:        "GL010",
	Title:     "Suppression without a reason",
	Severity:  model.Low,
	Platforms: "GitHub Actions, GitLab CI",
	Explanation: `A "# gatelint:ignore" comment must name the rule IDs it suppresses and give a reason of at least ` +
		`10 characters, so reviewers can tell a deliberate exception from a silenced warning. A suppression ` +
		`without a valid reason is reported by this rule and does not suppress anything; a suppression naming an ` +
		`unknown rule ID is reported as well. GL010 findings cannot themselves be suppressed.`,
	Hint: `add a reason of at least 10 characters after the rule IDs`,
	Before: `# gatelint:ignore GL004
continue-on-error: true`,
	After: `# gatelint:ignore GL004 nightly job only reports to the dashboard; the PR gate is in ci.yml
continue-on-error: true`,
})

func checkGL010(ctx *Context) []model.Finding {
	var out []model.Finding
	files := make([]string, 0, len(ctx.Directives))
	for f := range ctx.Directives {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		for _, d := range ctx.Directives[file] {
			var msgs []string
			if !d.Valid() {
				msgs = append(msgs, fmt.Sprintf("suppression %s, so it does not suppress anything", d.Problem))
			}
			for _, id := range d.Rules {
				if ByID(id) == nil {
					msgs = append(msgs, fmt.Sprintf("suppression names unknown rule %s", id))
				}
			}
			for _, m := range msgs {
				out = append(out, model.Finding{
					RuleID:     gl010.ID,
					Title:      gl010.Title,
					Severity:   gl010.Severity,
					Confidence: model.ConfidenceHigh,
					File:       d.File,
					Line:       d.Line,
					Column:     d.Column,
					Message:    m,
					Hint:       gl010.Hint,
					UseID:      -1,
				})
			}
		}
	}
	return out
}

// Exempt is the rule whose findings cannot be suppressed.
const Exempt = "GL010"

func init() { gl010.check = checkGL010 }
