package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

type painter bool

func (p painter) paint(code, s string) string {
	if !p || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (p painter) severity(s model.Severity) string {
	switch s {
	case model.High:
		return p.paint(ansiBold+ansiRed, s.Upper())
	case model.Medium:
		return p.paint(ansiYellow, s.Upper())
	case model.Low:
		return p.paint(ansiCyan, s.Upper())
	}
	return p.paint(ansiDim, s.Upper())
}

func (p painter) status(e model.CoverageEntry) string {
	label := string(e.Status)
	if len(e.Rules) > 0 {
		label += " (" + strings.Join(e.Rules, ", ") + ")"
	}
	switch e.Status {
	case model.StatusGating:
		return p.paint(ansiGreen, label)
	case model.StatusNeutered, model.StatusDisabled:
		return p.paint(ansiRed, label)
	case model.StatusNonGating:
		return p.paint(ansiYellow, label)
	}
	return p.paint(ansiDim, label)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-3]) + "..."
}

func pad(s string, visible, width int) string {
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

// Table writes the human-readable report.
func Table(w io.Writer, res *model.Result, opts Options) error {
	bw := bufio.NewWriter(w)
	lw := &errWriter{w: bw}
	p := painter(opts.Color)
	var shown []model.Finding
	for _, f := range res.Findings {
		if !f.Suppressed {
			shown = append(shown, f)
		}
	}

	if len(shown) > 0 {
		locW, whereW := len("LOCATION"), len("JOB / STEP")
		rows := make([][2]string, len(shown))
		for i, f := range shown {
			loc := f.Location()
			where := truncate(f.Where(), 48)
			rows[i] = [2]string{loc, where}
			if n := utf8.RuneCountInString(loc); n > locW {
				locW = n
			}
			if n := utf8.RuneCountInString(where); n > whereW {
				whereW = n
			}
		}
		indent := strings.Repeat(" ", 10)
		lw.printf("%s%s%s%s%s\n",
			pad(p.paint(ansiBold, "SEVERITY"), 8, 10),
			pad(p.paint(ansiBold, "RULE"), 4, 7),
			pad(p.paint(ansiBold, "LOCATION"), 8, locW+2),
			pad(p.paint(ansiBold, "JOB / STEP"), 10, whereW+2),
			p.paint(ansiBold, "MESSAGE"))
		for i, f := range shown {
			sev := f.Severity.Upper()
			msg := f.Message
			if f.Confidence == model.ConfidenceMedium {
				msg += " (confidence: medium)"
			}
			lw.printf("%s%s%s%s%s\n",
				pad(p.severity(f.Severity), len(sev), 10),
				pad(f.RuleID, len(f.RuleID), 7),
				pad(rows[i][0], utf8.RuneCountInString(rows[i][0]), locW+2),
				pad(rows[i][1], utf8.RuneCountInString(rows[i][1]), whereW+2),
				msg)
			for _, n := range f.Notes {
				lw.printf("%s%s\n", indent, p.paint(ansiDim, "note: "+n))
			}
			lw.printf("%s%s\n", indent, p.paint(ansiGreen, "fix: "+f.Hint))
		}
	}
	if opts.Quiet {
		return lw.flush(bw)
	}
	if len(shown) == 0 {
		lw.printf("No findings.\n")
	}

	if len(res.Coverage) > 0 {
		lw.printf("\n%s\n", p.paint(ansiBold, "Gate coverage"))
		for _, fc := range res.Coverage {
			lw.printf("  %s\n", fc.File)
			nameW, whereW := 0, 0
			for _, e := range fc.Scanners {
				if n := utf8.RuneCountInString(e.Scanner); n > nameW {
					nameW = n
				}
				if n := utf8.RuneCountInString(coverageWhere(e)); n > whereW {
					whereW = n
				}
			}
			for _, e := range fc.Scanners {
				where := coverageWhere(e)
				line := fmt.Sprintf("line %d", e.Line)
				lw.printf("    %s%s%s%s\n",
					pad(e.Scanner, utf8.RuneCountInString(e.Scanner), nameW+2),
					pad(where, utf8.RuneCountInString(where), whereW+2),
					pad(line, len(line), 11),
					p.status(e))
				if e.Note != "" {
					lw.printf("      %s\n", p.paint(ansiDim, e.Note))
				}
			}
		}
	}

	if len(res.Notes) > 0 {
		lw.printf("\n%s\n", p.paint(ansiBold, "Notes"))
		for _, n := range res.Notes {
			loc := n.File
			if n.Line > 0 {
				loc = fmt.Sprintf("%s:%d", n.File, n.Line)
			}
			lw.printf("  %s: %s\n", loc, n.Message)
		}
	}

	s := Summarize(res)
	lw.printf("\n%s %d %s (%d high, %d medium, %d low, %d info), %d suppressed; %d %s in %d %s",
		p.paint(ansiBold, "Summary:"), s.Findings, plural(s.Findings, "finding", "findings"),
		s.High, s.Medium, s.Low, s.Info, s.Suppressed,
		s.Scanners, plural(s.Scanners, "scanner", "scanners"), s.Files, plural(s.Files, "file", "files"))
	if s.Scanners > 0 {
		var parts []string
		for _, st := range []model.GateStatus{model.StatusGating, model.StatusNeutered, model.StatusNonGating, model.StatusDisabled, model.StatusUnknown} {
			if n := s.Status[string(st)]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, st))
			}
		}
		lw.printf(": %s", strings.Join(parts, ", "))
	}
	lw.printf("\n")
	return lw.flush(bw)
}

// errWriter remembers the first write error so the rendering code can stay
// linear.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, a...)
	}
}

func (e *errWriter) flush(bw *bufio.Writer) error {
	if e.err != nil {
		return e.err
	}
	return bw.Flush()
}

func coverageWhere(e model.CoverageEntry) string {
	switch {
	case e.Job != "" && e.Step != "":
		return truncate(e.Job+" / "+e.Step, 56)
	case e.Job != "":
		return truncate(e.Job, 56)
	case e.Step != "":
		return truncate(e.Step, 56)
	}
	return "(included template)"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
