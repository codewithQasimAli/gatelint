package shell

import (
	"regexp"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
)

var (
	fallbackSwallowRe = regexp.MustCompile(`\|\|\s*(true\b|:|exit\s+0\b|echo\b|printf\b|\$null\b|Write-(Host|Output|Warning)\b)`)
	fallbackSetRe     = regexp.MustCompile(`^\s*set\s+([-+][a-zA-Z]+)(\s+pipefail)?`)
	tokenRe           = regexp.MustCompile(`\S+`)
)

// fallback finds scanner invocations line by line. It is used for scripts the
// shell parser rejects and for non-POSIX shells. Every invocation it reports
// is marked Fallback so findings carry medium confidence.
func fallback(src string, ph *placeholders, opts Options) *Result {
	res := &Result{Fallback: true}
	errexit, pipefail := opts.Errexit, opts.Pipefail
	posix := opts.Dialect == Bash || opts.Dialect == POSIX
	reason := ""
	if !errexit && posix {
		reason = "the shell runs without errexit"
		if opts.ShellDesc != "" {
			reason = "the shell " + quote(opts.ShellDesc) + " runs without -e"
		}
	}
	errLine := 0
	lines := strings.Split(src, "\n")
	var last *Invocation
	for i, raw := range lines {
		lineNo := i + 1
		line := raw
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		text, _ := ph.restore(raw, opts.Env)
		res.Statements = append(res.Statements, Statement{Text: text, Line: lineNo})
		stmtIdx := len(res.Statements) - 1
		if last != nil && readsStatus(trimmed) {
			last.StatusChecked = true
		}
		last = nil
		if posix {
			if m := fallbackSetRe.FindStringSubmatch(trimmed); m != nil {
				flag := m[1]
				on := flag[0] == '-'
				if strings.Contains(flag, "e") {
					errexit = on
					if !on {
						reason = "\"set " + flag + "\""
						errLine = lineNo
					} else {
						errLine = 0
					}
				}
				if strings.Contains(flag, "o") && m[2] != "" {
					pipefail = on
				}
				continue
			}
		}
		for _, seg := range splitCommands(line) {
			words := tokenize(seg.text, lineNo, seg.col, ph, opts.Env)
			m, ok := opts.Catalog.MatchCommand(words)
			if !ok {
				continue
			}
			inv := &Invocation{
				Match:     m,
				Line:      m.Start.Line,
				Column:    m.Start.Column,
				Text:      text,
				Pipefail:  pipefail,
				StmtIndex: stmtIdx,
				Env:       copyEnv(opts.Env),
				Fallback:  true,
			}
			for k, v := range m.Env {
				inv.Env[k] = v
			}
			rest := line[seg.end:]
			if loc := fallbackSwallowRe.FindStringIndex(rest); loc != nil && strings.HasPrefix(strings.TrimSpace(rest), "|") {
				inv.Swallow = &Swallow{Kind: "or", Text: strings.TrimSpace(rest[loc[0]:]), Line: lineNo, Column: seg.end + loc[0] + 1}
			} else if strings.HasPrefix(strings.TrimSpace(rest), "|") && !strings.HasPrefix(strings.TrimSpace(rest), "||") {
				f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(rest), "|"))
				if len(f) > 0 {
					inv.PipedInto = f[0]
				}
			}
			if !errexit && posix {
				inv.ErrexitOff = true
				inv.ErrexitReason = reason
				inv.ErrexitLine = errLine
			}
			res.Invocations = append(res.Invocations, inv)
			last = inv
			break
		}
	}
	// The last statement's status is the script's status.
	if n := len(res.Statements); n > 0 {
		for _, inv := range res.Invocations {
			if inv.StmtIndex == n-1 {
				inv.Last = true
			}
		}
	}
	return res
}

type cmdSeg struct {
	text     string
	col, end int
}

// splitCommands splits a line at ";", "&&", "||" and "|" outside quotes.
func splitCommands(line string) []cmdSeg {
	var out []cmdSeg
	start := 0
	var q byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case q != 0:
			if ch == q {
				q = 0
			}
		case ch == '\'' || ch == '"':
			q = ch
		case ch == ';' || ch == '|' || ch == '&':
			out = append(out, cmdSeg{text: line[start:i], col: start + 1, end: i})
			if i+1 < len(line) && (line[i+1] == '|' || line[i+1] == '&') {
				i++
			}
			start = i + 1
		}
	}
	out = append(out, cmdSeg{text: line[start:], col: start + 1, end: len(line)})
	return out
}

func tokenize(s string, line, col int, ph *placeholders, env map[string]string) []catalog.Arg {
	var out []catalog.Arg
	for _, loc := range tokenRe.FindAllStringIndex(s, -1) {
		tok := strings.Trim(s[loc[0]:loc[1]], `"'`)
		v, known := ph.restore(tok, env)
		if strings.ContainsAny(v, "$`") {
			known = false
		}
		out = append(out, catalog.Arg{Value: v, Known: known, Line: line, Column: col + loc[0]})
	}
	return out
}
