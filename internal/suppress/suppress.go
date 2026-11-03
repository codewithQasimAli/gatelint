// Package suppress parses inline "# gatelint:ignore" comments and applies
// them to findings.
//
// A directive names one or more rule IDs, separated by commas, followed by a
// reason:
//
//	# gatelint:ignore GL001,GL004 report-only run; gating happens in the release job
//
// It applies to findings on the same line, or, when the comment is on a line
// of its own, to findings on the line directly below. A directive without a
// reason of at least MinReasonLength characters does not suppress anything.
package suppress

import (
	"regexp"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

// MinReasonLength is the minimum length of a suppression reason.
const MinReasonLength = 10

// Directive is one parsed suppression comment.
type Directive struct {
	File   string
	Line   int
	Column int
	Rules  []string
	Reason string
	// OwnLine is true when the comment is the only thing on its line.
	OwnLine bool
	// Problem is empty for a valid directive, otherwise it explains what is
	// wrong with it.
	Problem string
}

// Valid reports whether the directive may suppress findings.
func (d Directive) Valid() bool { return d.Problem == "" }

var (
	directiveRe = regexp.MustCompile(`(?:^|\s)#\s*gatelint:ignore\b(.*)$`)
	idsRe       = regexp.MustCompile(`(?i)^\s*(GL\d{3}(?:\s*,\s*GL\d{3})*)`)
	splitRe     = regexp.MustCompile(`\s*,\s*`)
)

// Parse extracts the directives from a file's contents.
func Parse(file string, data []byte) []Directive {
	var out []Directive
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for i, line := range strings.Split(text, "\n") {
		loc := directiveRe.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		hash := strings.Index(line[loc[0]:], "#") + loc[0]
		d := Directive{
			File:    file,
			Line:    i + 1,
			Column:  hash + 1,
			OwnLine: strings.TrimSpace(line[:hash]) == "",
		}
		rest := line[loc[2]:loc[3]]
		m := idsRe.FindStringSubmatchIndex(rest)
		if m == nil {
			d.Problem = "names no rule IDs"
			out = append(out, d)
			continue
		}
		for _, id := range splitRe.Split(rest[m[2]:m[3]], -1) {
			d.Rules = append(d.Rules, strings.ToUpper(strings.TrimSpace(id)))
		}
		reason := strings.TrimSpace(rest[m[1]:])
		reason = strings.TrimSpace(strings.TrimLeft(reason, "-:—"))
		d.Reason = reason
		switch {
		case reason == "":
			d.Problem = "has no reason"
		case len([]rune(reason)) < MinReasonLength:
			d.Problem = "has a reason shorter than 10 characters"
		}
		out = append(out, d)
	}
	return out
}

// appliesTo reports whether d covers a finding at line in file.
func (d Directive) appliesTo(f model.Finding) bool {
	if f.File != d.File {
		return false
	}
	if f.Line != d.Line && (!d.OwnLine || f.Line != d.Line+1) {
		return false
	}
	for _, r := range d.Rules {
		if r == f.RuleID {
			return true
		}
	}
	return false
}

// Apply marks findings covered by a valid directive as suppressed. Findings
// of the rule exempt (GL010) are never suppressed.
func Apply(findings []model.Finding, dirs map[string][]Directive, exempt string) {
	for i := range findings {
		f := &findings[i]
		if f.RuleID == exempt {
			continue
		}
		for _, d := range dirs[f.File] {
			if d.Valid() && d.appliesTo(*f) {
				f.Suppressed = true
				f.SuppressionReason = d.Reason
				break
			}
		}
	}
}
