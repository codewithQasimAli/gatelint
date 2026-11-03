package shell

import (
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
)

// maxNesting bounds recursion into "sh -c" strings.
const maxNesting = 4

type walker struct {
	src  string
	ph   *placeholders
	opts Options
	res  *Result

	errexit       bool
	errexitReason string
	errexitLine   int
	pipefail      bool
	env           map[string]string

	// lineOff and colOff shift positions for scripts nested in "sh -c".
	lineOff, colOff int
	nesting         int
	stmtIndex       int
}

// ctx is the context inherited by a statement from its parents.
type ctx struct {
	swallow *Swallow
	// guarded is true when a failure is handled by an enclosing construct
	// that fails the script (such as "|| exit 1").
	guarded   bool
	pipedInto string
	depth     int
	// cond is set inside if/while conditions; condFails records whether
	// the clause has a branch that exits with an error.
	cond      bool
	condFails bool
	// outputs are redirect and tee targets of the enclosing statements.
	outputs []string
}

type stmtInfo struct {
	last bool
	next *syntax.Stmt
}

func newWalker(src string, ph *placeholders, opts Options) *walker {
	w := &walker{src: src, ph: ph, opts: opts, res: &Result{}, errexit: opts.Errexit, pipefail: opts.Pipefail, env: copyEnv(opts.Env)}
	if !opts.Errexit {
		w.errexitReason = "the shell runs without errexit"
		if opts.ShellDesc != "" {
			w.errexitReason = "the shell " + quote(opts.ShellDesc) + " runs without -e"
		}
	}
	return w
}

func quote(s string) string { return `"` + s + `"` }

func (w *walker) line(p syntax.Pos) int { return int(p.Line()) + w.lineOff }

func (w *walker) col(p syntax.Pos) int {
	if int(p.Line()) == 1 {
		return int(p.Col()) + w.colOff
	}
	return int(p.Col())
}

func (w *walker) text(n syntax.Node) string {
	s, e := int(n.Pos().Offset()), int(n.End().Offset())
	if s < 0 || e > len(w.src) || s > e {
		return ""
	}
	t, _ := w.ph.restore(w.src[s:e], w.env)
	return t
}

func (w *walker) top(stmts []*syntax.Stmt) {
	for i, st := range stmts {
		w.stmtIndex = len(w.res.Statements)
		w.res.Statements = append(w.res.Statements, Statement{Text: w.text(st), Line: w.line(st.Pos())})
		si := stmtInfo{last: i == len(stmts)-1}
		if i+1 < len(stmts) {
			si.next = stmts[i+1]
		}
		w.stmt(st, ctx{}, si)
	}
}

func (w *walker) stmts(stmts []*syntax.Stmt, c ctx) {
	for i, st := range stmts {
		si := stmtInfo{}
		if i+1 < len(stmts) {
			si.next = stmts[i+1]
		}
		w.stmt(st, c, si)
	}
}

func (w *walker) stmt(st *syntax.Stmt, c ctx, si stmtInfo) {
	if st == nil || st.Cmd == nil {
		return
	}
	if st.Negated && !c.cond && c.swallow == nil {
		c.swallow = &Swallow{Kind: "negated", Text: "!", Line: w.line(st.Pos()), Column: w.col(st.Pos())}
	}
	for _, r := range st.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut:
			if r.Word != nil {
				if a := w.word(r.Word, w.env); a.Known && !strings.HasPrefix(a.Value, "/dev/") {
					c.outputs = append(append([]string{}, c.outputs...), a.Value)
				}
			}
		}
	}
	if st.Background && c.swallow == nil {
		c.swallow = &Swallow{Kind: "background", Text: "&", Line: w.line(st.Pos()), Column: w.col(st.Pos())}
	}
	w.command(st.Cmd, c, si)
}

func (w *walker) command(cmd syntax.Command, c ctx, si stmtInfo) {
	switch x := cmd.(type) {
	case *syntax.CallExpr:
		w.call(x, c, si)
	case *syntax.BinaryCmd:
		w.binary(x, c, si)
	case *syntax.Block:
		c.depth++
		w.stmts(x.Stmts, c)
	case *syntax.Subshell:
		c.depth++
		w.stmts(x.Stmts, c)
	case *syntax.IfClause:
		w.ifClause(x, c)
	case *syntax.WhileClause:
		cc := c
		cc.cond, cc.condFails = true, hasFailingExit(x.Do)
		cc.depth++
		w.stmts(x.Cond, cc)
		c.depth++
		w.stmts(x.Do, c)
	case *syntax.ForClause:
		c.depth++
		w.stmts(x.Do, c)
	case *syntax.CaseClause:
		c.depth++
		for _, item := range x.Items {
			w.stmts(item.Stmts, c)
		}
	case *syntax.FuncDecl:
		c.depth++
		w.stmt(x.Body, c, stmtInfo{})
	case *syntax.TimeClause:
		w.stmt(x.Stmt, c, si)
	case *syntax.DeclClause:
		w.decl(x, c)
	}
}

func (w *walker) binary(x *syntax.BinaryCmd, c ctx, si stmtInfo) {
	switch x.Op {
	case syntax.OrStmt:
		cx := c
		if w.alwaysSucceeds(x.Y) {
			cx.swallow = &Swallow{Kind: "or", Text: "|| " + w.text(x.Y), Line: w.line(x.OpPos), Column: w.col(x.OpPos)}
		} else {
			cx.guarded = true
		}
		w.stmt(x.X, cx, stmtInfo{})
		w.stmt(x.Y, c, si)
	case syntax.AndStmt:
		cx := c
		if cx.swallow == nil && !cx.guarded && !cx.cond && cx.depth == 0 && !si.last && w.errexit {
			cx.swallow = &Swallow{Kind: "and", Text: "&& " + w.text(x.Y), Line: w.line(x.OpPos), Column: w.col(x.OpPos)}
		}
		w.stmt(x.X, cx, stmtInfo{})
		w.stmt(x.Y, c, si)
	case syntax.Pipe, syntax.PipeAll:
		cx := c
		cx.pipedInto = firstWord(x.Y)
		cx.outputs = append(append([]string{}, c.outputs...), w.teeFiles(x.Y)...)
		w.stmt(x.X, cx, stmtInfo{})
		w.stmt(x.Y, c, si)
	}
}

// teeFiles returns the file arguments of a "tee" command.
func (w *walker) teeFiles(st *syntax.Stmt) []string {
	ce, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Args) == 0 || path.Base(ce.Args[0].Lit()) != "tee" {
		return nil
	}
	var out []string
	for _, a := range ce.Args[1:] {
		v := w.word(a, w.env)
		if v.Known && !strings.HasPrefix(v.Value, "-") && !strings.HasPrefix(v.Value, "/dev/") {
			out = append(out, v.Value)
		}
	}
	return out
}

func (w *walker) ifClause(x *syntax.IfClause, c ctx) {
	fails := false
	for cl := x; cl != nil; cl = cl.Else {
		if hasFailingExit(cl.Then) {
			fails = true
		}
	}
	for cl := x; cl != nil; cl = cl.Else {
		if len(cl.Cond) > 0 {
			cc := c
			cc.cond, cc.condFails = true, fails
			cc.depth++
			w.stmts(cl.Cond, cc)
		}
		b := c
		b.depth++
		w.stmts(cl.Then, b)
	}
}

func (w *walker) decl(x *syntax.DeclClause, c ctx) {
	variant := ""
	if x.Variant != nil {
		variant = x.Variant.Value
	}
	for _, as := range x.Args {
		if as.Value == nil {
			continue
		}
		if c.depth == 0 && as.Name != nil {
			if a := w.word(as.Value, w.env); a.Known {
				w.env[as.Name.Value] = a.Value
			} else {
				delete(w.env, as.Name.Value)
			}
		}
		cc := c
		if cc.swallow == nil {
			cc.swallow = &Swallow{Kind: "subst", Text: variant, Line: w.line(x.Pos()), Column: w.col(x.Pos())}
		}
		w.substs(as.Value, cc)
	}
}

// substs walks command substitutions inside a word.
func (w *walker) substs(word *syntax.Word, c ctx) {
	if word == nil {
		return
	}
	var parts func([]syntax.WordPart)
	parts = func(ps []syntax.WordPart) {
		for _, p := range ps {
			switch p := p.(type) {
			case *syntax.DblQuoted:
				parts(p.Parts)
			case *syntax.CmdSubst:
				cc := c
				cc.depth++
				cc.pipedInto = ""
				w.stmts(p.Stmts, cc)
			case *syntax.ProcSubst:
				cc := c
				cc.depth++
				if cc.swallow == nil {
					cc.swallow = &Swallow{Kind: "subst", Text: "process substitution", Line: w.line(p.Pos()), Column: w.col(p.Pos())}
				}
				w.stmts(p.Stmts, cc)
			}
		}
	}
	parts(word.Parts)
}

func (w *walker) call(x *syntax.CallExpr, c ctx, si stmtInfo) {
	env := w.env
	if len(x.Assigns) > 0 {
		env = copyEnv(w.env)
		for _, as := range x.Assigns {
			if as.Name == nil || as.Value == nil {
				continue
			}
			if a := w.word(as.Value, w.env); a.Known {
				env[as.Name.Value] = a.Value
			}
		}
	}
	if len(x.Args) == 0 {
		// Plain assignment: its status is that of the last command
		// substitution, so errexit still applies.
		for _, as := range x.Assigns {
			if as.Value != nil {
				w.substs(as.Value, c)
			}
		}
		if c.depth == 0 {
			for k, v := range env {
				w.env[k] = v
			}
		}
		return
	}
	args := make([]catalog.Arg, len(x.Args))
	for i, a := range x.Args {
		args[i] = w.word(a, env)
	}
	// Command substitutions in arguments: the outer command's status wins.
	for _, a := range x.Args {
		cc := c
		if cc.swallow == nil {
			cc.swallow = &Swallow{Kind: "subst", Text: firstLiteral(args), Line: w.line(x.Pos()), Column: w.col(x.Pos())}
		}
		w.substs(a, cc)
	}
	name := path.Base(args[0].Value)
	switch name {
	case "set":
		w.applySet(args, w.line(x.Pos()))
		return
	case "export":
		if c.depth == 0 {
			for _, a := range args[1:] {
				if k, v, ok := strings.Cut(a.Value, "="); ok && a.Known {
					w.env[k] = v
				}
			}
		}
		return
	case "sh", "bash", "dash", "zsh", "ash":
		if w.nestedScript(args, c, si) {
			return
		}
	}
	m, ok := w.opts.Catalog.MatchCommand(args)
	if !ok {
		return
	}
	callEnv := copyEnv(env)
	for k, v := range m.Env {
		callEnv[k] = v
	}
	inv := &Invocation{
		Match:     m,
		Line:      m.Start.Line,
		Column:    m.Start.Column,
		Text:      w.res.Statements[w.stmtIndexSafe()].Text,
		Swallow:   c.swallow,
		PipedInto: c.pipedInto,
		Pipefail:  w.pipefail,
		Last:      si.last && c.depth == 0,
		StmtIndex: w.stmtIndex,
		Env:       callEnv,
		Outputs:   c.outputs,
	}
	if inv.Line == 0 {
		inv.Line, inv.Column = w.line(x.Pos()), w.col(x.Pos())
	}
	if c.cond && !c.condFails && inv.Swallow == nil {
		inv.Swallow = &Swallow{Kind: "if", Text: "if", Line: inv.Line, Column: inv.Column}
	}
	if !w.errexit {
		inv.ErrexitOff = true
		inv.ErrexitReason = w.errexitReason
		inv.ErrexitLine = w.errexitLine
	}
	if si.next != nil && readsStatus(w.text(si.next)) {
		inv.StatusChecked = true
	}
	w.res.Invocations = append(w.res.Invocations, inv)
}

func (w *walker) stmtIndexSafe() int {
	if w.stmtIndex < len(w.res.Statements) {
		return w.stmtIndex
	}
	return 0
}

var statusRe = regexp.MustCompile(`\$\?|\$\{\?\}|PIPESTATUS`)

func readsStatus(s string) bool { return statusRe.MatchString(s) }

// nestedScript analyses "bash -c 'script'" and reports whether it did.
func (w *walker) nestedScript(args []catalog.Arg, c ctx, si stmtInfo) bool {
	if w.nesting >= maxNesting {
		return false
	}
	errexit, pipefail := false, false
	for i := 1; i < len(args); i++ {
		a := args[i].Value
		if a == "-c" || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.HasSuffix(a, "c")) {
			if strings.Contains(a, "e") {
				errexit = true
			}
			if i+1 >= len(args) || !args[i+1].Known {
				return false
			}
			script := args[i+1]
			inner := Options{Dialect: Bash, Errexit: errexit, Pipefail: pipefail, ShellDesc: args[0].Value + " -c", Env: w.env, Catalog: w.opts.Catalog}
			sub, ph := substitute(script.Value)
			f, err := syntax.NewParser().Parse(strings.NewReader(sub), "")
			if err != nil {
				return false
			}
			nw := newWalker(sub, ph, inner)
			nw.nesting = w.nesting + 1
			nw.lineOff = script.Line - 1
			nw.colOff = script.Column
			nw.top(f.Stmts)
			for _, inv := range nw.res.Invocations {
				if inv.Swallow == nil {
					inv.Swallow = c.swallow
				}
				if inv.PipedInto == "" {
					inv.PipedInto = c.pipedInto
				}
				// The nested shell's status is that of its last command.
				inv.Last = inv.Last && si.last && c.depth == 0
				inv.StmtIndex = w.stmtIndex
				inv.Text = w.res.Statements[w.stmtIndexSafe()].Text
				if c.cond && !c.condFails && inv.Swallow == nil {
					inv.Swallow = &Swallow{Kind: "if", Text: "if", Line: inv.Line, Column: inv.Column}
				}
				if inv.ErrexitOff && inv.Last {
					inv.ErrexitOff = false
				}
				if si.next != nil && readsStatus(w.text(si.next)) {
					inv.StatusChecked = true
				}
				w.res.Invocations = append(w.res.Invocations, inv)
			}
			return true
		}
		if a == "-o" && i+1 < len(args) {
			if args[i+1].Value == "pipefail" {
				pipefail = true
			}
			if args[i+1].Value == "errexit" {
				errexit = true
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-") && strings.Contains(a, "e") && !strings.HasPrefix(a, "--") {
			errexit = true
		}
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return false
}

func (w *walker) applySet(args []catalog.Arg, line int) {
	for i := 1; i < len(args); i++ {
		a := args[i].Value
		if a == "--" || len(a) < 2 || (a[0] != '-' && a[0] != '+') {
			continue
		}
		on := a[0] == '-'
		for _, ch := range a[1:] {
			switch ch {
			case 'e':
				w.setErrexit(on, line, a)
			case 'o':
				if i+1 < len(args) {
					i++
					switch args[i].Value {
					case "pipefail":
						w.pipefail = on
					case "errexit":
						w.setErrexit(on, line, a+" errexit")
					}
				}
			}
		}
	}
}

func (w *walker) setErrexit(on bool, line int, flag string) {
	w.errexit = on
	if on {
		w.errexitReason, w.errexitLine = "", 0
		return
	}
	w.errexitReason = "\"set " + flag + "\""
	w.errexitLine = line
}

// word renders a shell word to a literal where possible.
func (w *walker) word(word *syntax.Word, env map[string]string) catalog.Arg {
	a := catalog.Arg{Known: true, Line: w.line(word.Pos()), Column: w.col(word.Pos())}
	var sb strings.Builder
	var parts func([]syntax.WordPart, bool)
	parts = func(ps []syntax.WordPart, quoted bool) {
		for _, p := range ps {
			switch p := p.(type) {
			case *syntax.Lit:
				sb.WriteString(unescape(p.Value, quoted))
			case *syntax.SglQuoted:
				sb.WriteString(p.Value)
			case *syntax.DblQuoted:
				parts(p.Parts, true)
			case *syntax.ParamExp:
				if p.Param != nil && p.Exp == nil && p.Repl == nil && p.Slice == nil && p.Index == nil && !p.Length && !p.Excl && !p.Width {
					if v, ok := env[p.Param.Value]; ok {
						sb.WriteString(v)
						continue
					}
				}
				a.Known = false
				sb.WriteString(w.rawText(p))
			default:
				a.Known = false
				sb.WriteString(w.rawText(p))
			}
		}
	}
	parts(word.Parts, false)
	v, known := w.ph.restore(sb.String(), env)
	a.Value = v
	a.Known = a.Known && known
	return a
}

func (w *walker) rawText(n syntax.Node) string {
	s, e := int(n.Pos().Offset()), int(n.End().Offset())
	if s < 0 || e > len(w.src) || s > e {
		return ""
	}
	return w.src[s:e]
}

func unescape(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if !quoted || strings.IndexByte("\"\\$`\n", next) >= 0 {
				if next != '\n' {
					b.WriteByte(next)
				}
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// alwaysSucceeds reports whether a statement on the right of "||" can never
// fail, so that the left side's failure is discarded.
func (w *walker) alwaysSucceeds(st *syntax.Stmt) bool {
	if st == nil || st.Negated {
		return false
	}
	switch x := st.Cmd.(type) {
	case *syntax.CallExpr:
		if len(x.Args) == 0 {
			// rc=$? captures the status; it is handled if rc is used later.
			for _, as := range x.Assigns {
				if as.Name != nil && w.referencedAfter(as.Name.Value, int(st.End().Offset())) {
					return false
				}
			}
			return true
		}
		name := path.Base(firstLiteral([]catalog.Arg{w.word(x.Args[0], w.env)}))
		switch name {
		case "true", ":", "echo", "printf":
			return true
		case "exit", "return":
			if len(x.Args) > 1 {
				return w.word(x.Args[1], w.env).Value == "0"
			}
			return false
		}
		return false
	case *syntax.Block:
		return len(x.Stmts) > 0 && w.alwaysSucceeds(x.Stmts[len(x.Stmts)-1]) && !hasFailingExit(x.Stmts)
	case *syntax.Subshell:
		return len(x.Stmts) > 0 && w.alwaysSucceeds(x.Stmts[len(x.Stmts)-1]) && !hasFailingExit(x.Stmts)
	case *syntax.BinaryCmd:
		switch x.Op {
		case syntax.AndStmt:
			return w.alwaysSucceeds(x.X) && w.alwaysSucceeds(x.Y)
		case syntax.OrStmt:
			return w.alwaysSucceeds(x.Y)
		default:
			return w.alwaysSucceeds(x.Y)
		}
	case *syntax.DeclClause:
		return true
	}
	return false
}

func (w *walker) referencedAfter(name string, offset int) bool {
	if offset >= len(w.src) {
		return false
	}
	re := regexp.MustCompile(`\$\{?` + regexp.QuoteMeta(name) + `\b`)
	return re.MatchString(w.src[offset:])
}

// hasFailingExit reports whether statements contain "exit N" with N other
// than 0, a bare "exit", "false" or "return N" with N other than 0.
func hasFailingExit(stmts []*syntax.Stmt) bool {
	found := false
	for _, st := range stmts {
		syntax.Walk(st, func(n syntax.Node) bool {
			if found {
				return false
			}
			ce, ok := n.(*syntax.CallExpr)
			if !ok || len(ce.Args) == 0 {
				return true
			}
			name := ce.Args[0].Lit()
			switch name {
			case "false":
				found = true
			case "exit", "return":
				if len(ce.Args) == 1 || ce.Args[1].Lit() != "0" {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func firstWord(st *syntax.Stmt) string {
	if st == nil {
		return ""
	}
	var out string
	syntax.Walk(st, func(n syntax.Node) bool {
		if out != "" {
			return false
		}
		if ce, ok := n.(*syntax.CallExpr); ok && len(ce.Args) > 0 {
			out = ce.Args[0].Lit()
			if out == "" {
				out = "command"
			}
			return false
		}
		return true
	})
	return out
}

func firstLiteral(args []catalog.Arg) string {
	if len(args) == 0 {
		return ""
	}
	return args[0].Value
}
