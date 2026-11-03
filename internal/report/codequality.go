package report

import (
	"encoding/json"
	"io"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

// CodeQualityIssue is one entry of a GitLab Code Quality report.
type CodeQualityIssue struct {
	Type        string              `json:"type"`
	CheckName   string              `json:"check_name"`
	Description string              `json:"description"`
	Content     CodeQualityContent  `json:"content"`
	Categories  []string            `json:"categories"`
	Fingerprint string              `json:"fingerprint"`
	Severity    string              `json:"severity"`
	Location    CodeQualityLocation `json:"location"`
}

// CodeQualityContent holds the fix hint.
type CodeQualityContent struct {
	Body string `json:"body"`
}

// CodeQualityLocation is a file and line.
type CodeQualityLocation struct {
	Path  string           `json:"path"`
	Lines CodeQualityLines `json:"lines"`
}

// CodeQualityLines holds the first line of an issue.
type CodeQualityLines struct {
	Begin int `json:"begin"`
}

// CodeQualitySeverity maps a severity to GitLab's scale.
func CodeQualitySeverity(s model.Severity) string {
	switch s {
	case model.High:
		return "critical"
	case model.Medium:
		return "major"
	case model.Low:
		return "minor"
	}
	return "info"
}

// BuildCodeQuality converts unsuppressed findings into Code Quality issues.
func BuildCodeQuality(res *model.Result) []CodeQualityIssue {
	out := []CodeQualityIssue{}
	for _, f := range res.Findings {
		if f.Suppressed {
			continue
		}
		out = append(out, CodeQualityIssue{
			Type:        "issue",
			CheckName:   f.RuleID,
			Description: f.RuleID + ": " + f.Message,
			Content:     CodeQualityContent{Body: "Fix: " + f.Hint},
			Categories:  []string{"Security"},
			Fingerprint: f.Fingerprint,
			Severity:    CodeQualitySeverity(f.Severity),
			Location:    CodeQualityLocation{Path: f.File, Lines: CodeQualityLines{Begin: f.Line}},
		})
	}
	return out
}

// CodeQuality writes a GitLab Code Quality report. Suppressed findings are
// left out because the format has no notion of suppression.
func CodeQuality(w io.Writer, res *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(BuildCodeQuality(res))
}
