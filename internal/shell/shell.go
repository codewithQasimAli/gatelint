// Package shell parses the shell scripts in CI steps and reports every
// scanner invocation together with the shell context that decides whether a
// failing scan can fail the step: "|| true" and similar, errexit, pipefail,
// negation, command substitution and background execution.
package shell

import (
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
)

// Dialect is the shell language a script is written in.
type Dialect int

// Supported dialects.
const (
	Bash Dialect = iota
	POSIX
	PowerShell
	Other
)

// Options control the analysis of one script.
type Options struct {
	Dialect Dialect
	// Errexit and Pipefail are the options the shell starts with.
	Errexit  bool
	Pipefail bool
	// ShellDesc describes the shell for messages, e.g. "bash -e {0}".
	ShellDesc string
	// Env holds known environment variables.
	Env     map[string]string
	Catalog *catalog.Catalog
}

// Swallow describes why a scanner's exit status cannot fail the script.
type Swallow struct {
	// Kind is one of: or, negated, and, if, subst, background.
	Kind string
	// Text is the construct that swallows the failure, e.g. "|| true".
	Text   string
	Line   int
	Column int
}

// Invocation is a scanner command found in a script. Positions are relative
// to the script (1-based).
type Invocation struct {
	Match  *catalog.Match
	Line   int
	Column int
	// Text is the source of the enclosing top-level statement.
	Text          string
	Swallow       *Swallow
	PipedInto     string
	Pipefail      bool
	ErrexitOff    bool
	ErrexitReason string
	// ErrexitLine is the script line of the "set +e" that disabled
	// errexit, or 0 when the shell started without it.
	ErrexitLine int
	// StatusChecked is true when the next statement reads $?.
	StatusChecked bool
	// Last is true when the invocation's statement is the last top-level
	// statement, so its status becomes the script's status.
	Last bool
	// StmtIndex is the index of the enclosing top-level statement.
	StmtIndex int
	// Env is the effective known environment at the call.
	Env map[string]string
	// Fallback is true when the script could not be parsed and the
	// invocation was found by line-based heuristics.
	Fallback bool
	// Outputs are files the scanner's output is written to by a shell
	// redirect or tee.
	Outputs []string
}

// Statement is a top-level statement of a script.
type Statement struct {
	Text string
	Line int
}

// Result is the analysis of one script.
type Result struct {
	Invocations []*Invocation
	Statements  []Statement
	Fallback    bool
	ParseError  string
}

// placeholders replaces CI expressions with shell-safe words of the same
// length so the parser accepts the script and columns stay accurate.
type placeholders struct {
	orig  map[string]string
	order []string
}

var exprRe = regexp.MustCompile(`(?s)\$\{\{.*?\}\}|\$\[\[.*?\]\]`)

func substitute(src string) (string, *placeholders) {
	ph := &placeholders{orig: map[string]string{}}
	i := 0
	out := exprRe.ReplaceAllStringFunc(src, func(m string) string {
		tok := fmt.Sprintf("GLX%dZ", i)
		i++
		// Pad single-line expressions so columns after them stay exact.
		if !strings.Contains(m, "\n") && len(m) > len(tok) {
			tok += strings.Repeat("Z", len(m)-len(tok))
		}
		ph.orig[tok] = m
		ph.order = append(ph.order, tok)
		return tok
	})
	return out, ph
}

var envExprRe = regexp.MustCompile(`^\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$`)

// restore puts the original expressions back. It reports whether the result
// is fully known: expressions are unknown unless they are ${{ env.NAME }}
// with a known value.
func (ph *placeholders) restore(s string, env map[string]string) (string, bool) {
	known := true
	for i := len(ph.order) - 1; i >= 0; i-- {
		tok := ph.order[i]
		if !strings.Contains(s, tok) {
			continue
		}
		orig := ph.orig[tok]
		if m := envExprRe.FindStringSubmatch(orig); m != nil {
			if v, ok := env[m[1]]; ok && !strings.Contains(v, "${{") {
				s = strings.ReplaceAll(s, tok, v)
				continue
			}
		}
		known = false
		s = strings.ReplaceAll(s, tok, orig)
	}
	return s, known
}

// Analyze parses a script and returns the scanner invocations in it.
func Analyze(src string, opts Options) *Result {
	if opts.Catalog == nil {
		opts.Catalog = catalog.Default()
	}
	sub, ph := substitute(src)
	if opts.Dialect == PowerShell || opts.Dialect == Other {
		return fallback(sub, ph, opts)
	}
	lang := syntax.LangBash
	if opts.Dialect == POSIX {
		lang = syntax.LangPOSIX
	}
	f, err := syntax.NewParser(syntax.Variant(lang)).Parse(strings.NewReader(sub), "")
	if err != nil && lang == syntax.LangPOSIX {
		// Many "sh" scripts use bash syntax that dash would also reject;
		// the bash parser is a better approximation than giving up.
		f, err = syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(sub), "")
	}
	if err != nil {
		r := fallback(sub, ph, opts)
		r.ParseError = err.Error()
		return r
	}
	w := newWalker(sub, ph, opts)
	w.top(f.Stmts)
	return w.res
}

func copyEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}
