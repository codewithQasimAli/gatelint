// Package report renders scan results as a terminal table, JSON, SARIF 2.1.0
// or GitLab Code Quality JSON.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "sarif", "codequality"}

// Options control rendering.
type Options struct {
	Color   bool
	Quiet   bool
	Version string
}

// Write renders res in the given format.
func Write(w io.Writer, format string, res *model.Result, opts Options) error {
	switch strings.ToLower(format) {
	case "table", "":
		return Table(w, res, opts)
	case "json":
		return JSON(w, res, opts)
	case "sarif":
		return SARIF(w, res, opts)
	case "codequality":
		return CodeQuality(w, res)
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}

// Summary is the aggregate counts of a result.
type Summary struct {
	Findings   int            `json:"findings"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	Info       int            `json:"info"`
	Suppressed int            `json:"suppressed"`
	Files      int            `json:"files"`
	Scanners   int            `json:"scanners"`
	Status     map[string]int `json:"status"`
}

// Summarize counts findings and coverage entries.
func Summarize(res *model.Result) Summary {
	by, sup := res.Counts()
	s := Summary{
		High: by[model.High], Medium: by[model.Medium], Low: by[model.Low], Info: by[model.Info],
		Suppressed: sup, Files: len(res.Files), Status: map[string]int{},
	}
	s.Findings = s.High + s.Medium + s.Low + s.Info
	for _, st := range []model.GateStatus{model.StatusGating, model.StatusNeutered, model.StatusNonGating, model.StatusDisabled, model.StatusUnknown} {
		s.Status[string(st)] = 0
	}
	for _, fc := range res.Coverage {
		for _, e := range fc.Scanners {
			s.Scanners++
			s.Status[string(e.Status)]++
		}
	}
	return s
}
