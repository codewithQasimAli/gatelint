package report

import (
	"encoding/json"
	"io"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

type jsonReport struct {
	Tool     jsonTool             `json:"tool"`
	Summary  Summary              `json:"summary"`
	Files    []string             `json:"files"`
	Findings []model.Finding      `json:"findings"`
	Coverage []model.FileCoverage `json:"coverage"`
	Notes    []model.Note         `json:"notes"`
	Errors   []model.FileError    `json:"errors"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// JSON writes the full result, including suppressed findings and the gate
// coverage summary.
func JSON(w io.Writer, res *model.Result, opts Options) error {
	r := jsonReport{
		Tool:     jsonTool{Name: "gatelint", Version: opts.Version},
		Summary:  Summarize(res),
		Files:    nonNil(res.Files),
		Findings: res.Findings,
		Coverage: res.Coverage,
		Notes:    res.Notes,
		Errors:   res.Errors,
	}
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	if r.Coverage == nil {
		r.Coverage = []model.FileCoverage{}
	}
	if r.Notes == nil {
		r.Notes = []model.Note{}
	}
	if r.Errors == nil {
		r.Errors = []model.FileError{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
