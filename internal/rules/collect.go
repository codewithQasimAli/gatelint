package rules

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/shell"
)

// RepoFiles reports whether a file exists at a pipeline's repository root.
type RepoFiles func(p *model.Pipeline, name string) bool

// Collect finds every scanner use in the pipelines and fills ctx.Uses and
// ctx.Events.
func Collect(ctx *Context, repoFiles RepoFiles) {
	if ctx.Events == nil {
		ctx.Events = map[*model.Job][]Event{}
	}
	c := &collector{ctx: ctx, repoFiles: repoFiles}
	for _, p := range ctx.Pipelines {
		c.pipeline(p)
	}
}

type collector struct {
	ctx       *Context
	repoFiles RepoFiles
	p         *model.Pipeline
}

func (c *collector) files() func(string) bool {
	if c.repoFiles == nil {
		return nil
	}
	p := c.p
	return func(name string) bool { return c.repoFiles(p, name) }
}

func (c *collector) add(u *Use) {
	u.ID = len(c.ctx.Uses)
	u.Pipeline = c.p
	if u.Confidence == "" {
		u.Confidence = model.ConfidenceHigh
	}
	c.ctx.Uses = append(c.ctx.Uses, u)
}

func (c *collector) event(job *model.Job, e Event) {
	c.ctx.Events[job] = append(c.ctx.Events[job], e)
}

func (c *collector) pipeline(p *model.Pipeline) {
	c.p = p
	switch p.Platform {
	case model.GitHub:
		for _, job := range p.Jobs {
			c.githubJob(job)
		}
	case model.GitLab:
		c.gitlab(p)
	}
}

// knownEnv merges env maps (later maps win) into plain strings.
func knownEnv(maps ...map[string]model.Value) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v.Raw
		}
	}
	return out
}

func (c *collector) githubJob(job *model.Job) {
	windows := strings.Contains(strings.ToLower(job.RunsOn), "windows")
	for _, st := range job.Steps {
		order := st.Index * 100000
		env := knownEnv(c.p.Env, job.Env, st.Env)
		if st.Uses.Set {
			c.githubAction(job, st, env, order)
		}
		if st.Run == nil {
			continue
		}
		shellVal := st.Shell.Raw
		if !st.Shell.Set {
			shellVal = job.DefaultShell.Raw
		}
		opts := shell.GitHubOptions(shellVal, windows)
		opts.Env = env
		opts.Catalog = c.ctx.Catalog
		sm := newScriptMap(st.Run.Segments)
		res := shell.Analyze(sm.text, opts)
		for i, s := range res.Statements {
			c.event(job, Event{Order: order + i + 1, Group: st.Index, Text: s.Text, Pos: sm.pos(s.Line, 1)})
		}
		for _, inv := range res.Invocations {
			c.cliUse(job, st, "run", inv, sm, order+inv.StmtIndex+1)
		}
	}
}

func (c *collector) cliUse(job *model.Job, st *model.Step, section string, inv *shell.Invocation, sm *scriptMap, order int) {
	u := &Use{
		Tool:    inv.Match.Tool,
		Kind:    "cli",
		Job:     job,
		Step:    st,
		Section: section,
		Pos:     sm.pos(inv.Line, inv.Column),
		Inv:     inv,
		Eval:    inv.Match.Tool.Evaluate(inv.Match.Args, inv.Env, c.files()),
		Order:   order,
	}
	u.Eval.Outputs = append(u.Eval.Outputs, inv.Outputs...)
	if inv.Fallback {
		u.Confidence = model.ConfidenceMedium
	}
	// Map argument positions back to the file.
	for i := range inv.Match.Args {
		a := &inv.Match.Args[i]
		p := sm.pos(a.Line, a.Column)
		a.Line, a.Column = p.Line, p.Column
	}
	for _, h := range [][]catalog.Hit{u.Eval.Neuters, u.Eval.Gates, u.Eval.Unknown} {
		for i := range h {
			if h[i].Arg.Line > 0 && !h[i].FromEnv {
				p := sm.pos(h[i].Arg.Line, h[i].Arg.Column)
				h[i].Arg.Line, h[i].Arg.Column = p.Line, p.Column
			}
		}
	}
	if inv.ErrexitLine > 0 {
		inv.ErrexitLine = sm.pos(inv.ErrexitLine, 1).Line
	}
	if inv.Swallow != nil {
		p := sm.pos(inv.Swallow.Line, inv.Swallow.Column)
		inv.Swallow.Line, inv.Swallow.Column = p.Line, p.Column
	}
	u.ArgsPos = u.Pos
	c.add(u)
}

func (c *collector) githubAction(job *model.Job, st *model.Step, env map[string]string, order int) {
	ref := strings.TrimSpace(st.Uses.Raw)
	inputs := map[string]catalog.InputValue{}
	inputPos := map[string]model.Pos{}
	for _, in := range st.With {
		inputs[in.Name] = catalog.InputValue{Value: in.Value.Raw, Known: !strings.Contains(in.Value.Raw, "${{")}
		inputPos[strings.ToLower(in.Name)] = in.Value.Pos
	}
	ev := Event{Order: order, Group: st.Index, Uses: ref, Inputs: map[string]string{}, Pos: st.Uses.Pos, Text: "uses: " + ref}
	for k, v := range inputs {
		ev.Inputs[strings.ToLower(k)] = v.Value
		ev.Text += " " + k + "=" + v.Value
	}
	c.event(job, ev)

	if strings.HasPrefix(strings.ToLower(ref), "docker://") {
		t := c.ctx.Catalog.Image(ref)
		if t == nil {
			return
		}
		argsVal, argsPos := inputs["args"], inputPos["args"]
		var args []catalog.Arg
		if argsVal.Value != "" {
			args = splitArgs(argsVal.Value, argsVal.Known, argsPos)
		}
		if ep, ok := inputs["entrypoint"]; ok && ep.Value != "" {
			if m, ok := c.ctx.Catalog.MatchCommand(append(catalog.Lit(ep.Value), args...)); ok && m.Tool == t {
				args = m.Args
			}
		} else if len(args) > 0 {
			if m, ok := c.ctx.Catalog.MatchCommand(args); ok && m.Tool == t {
				args = m.Args
			}
		}
		u := &Use{Tool: t, Kind: "cli", Job: job, Step: st, Section: "run", Pos: st.Uses.Pos, Order: order, ArgsPos: argsPos, InputPos: inputPos}
		if u.ArgsPos.IsZero() {
			u.ArgsPos = st.Uses.Pos
		}
		u.Eval = t.Evaluate(args, env, c.files())
		for i := range u.Eval.Neuters {
			u.Eval.Neuters[i].Arg.Line, u.Eval.Neuters[i].Arg.Column = u.ArgsPos.Line, u.ArgsPos.Column
		}
		c.add(u)
		return
	}
	t, a := c.ctx.Catalog.Action(ref)
	if t == nil {
		return
	}
	var args []catalog.Arg
	if a.ArgsInput != "" {
		if v, ok := inputs[a.ArgsInput]; ok {
			args = splitArgs(v.Value, v.Known, inputPos[strings.ToLower(a.ArgsInput)])
		}
	}
	u := &Use{Tool: t, Kind: "action", Job: job, Step: st, Section: "uses", Pos: st.Uses.Pos, Action: a, InputPos: inputPos, Order: order}
	if a.ArgsInput != "" {
		u.ArgsPos = inputPos[strings.ToLower(a.ArgsInput)]
	}
	u.Eval = t.EvaluateAction(a, inputs, args, env, c.files())
	c.add(u)
}

// splitArgs tokenises an action input that holds command-line arguments.
func splitArgs(s string, known bool, pos model.Pos) []catalog.Arg {
	var out []catalog.Arg
	f, err := syntax.NewParser().Parse(strings.NewReader(s), "")
	if err == nil {
		syntax.Walk(f, func(n syntax.Node) bool {
			ce, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			for _, w := range ce.Args {
				lit := w.Lit()
				k := known
				if lit == "" {
					lit = wordString(s, w)
					k = false
				}
				if strings.Contains(lit, "${{") {
					k = false
				}
				out = append(out, catalog.Arg{Value: lit, Known: k, Line: pos.Line, Column: pos.Column})
			}
			return false
		})
		if len(out) > 0 {
			return out
		}
	}
	for _, w := range strings.Fields(s) {
		out = append(out, catalog.Arg{Value: strings.Trim(w, `"'`), Known: known && !strings.Contains(w, "${{"), Line: pos.Line, Column: pos.Column})
	}
	return out
}

func wordString(src string, w *syntax.Word) string {
	s, e := int(w.Pos().Offset()), int(w.End().Offset())
	if s < 0 || e > len(src) || s > e {
		return ""
	}
	v := src[s:e]
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return v
}

func (c *collector) gitlab(p *model.Pipeline) {
	included := map[string]model.TemplateUse{}
	for _, tu := range p.Templates {
		if tpl := c.ctx.Catalog.Template(tu.Name); tpl != nil {
			if _, ok := included[tpl.ID]; !ok {
				included[tpl.ID] = tu
			}
		}
	}
	overridden := map[string]bool{}
	for _, job := range p.Jobs {
		if tpl := c.ctx.Catalog.TemplateForJob(job.ID); tpl != nil {
			if _, ok := included[tpl.ID]; ok && len(job.Scripts) == 0 {
				job.Template = tpl.ID
				overridden[tpl.ID] = true
				c.add(&Use{Template: tpl, Kind: "template", Job: job, Pos: job.Pos})
				continue
			}
		}
		c.gitlabJob(job)
	}
	ids := make([]string, 0, len(included))
	for id := range included {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return included[ids[i]].Pos.Line < included[ids[j]].Pos.Line })
	for _, id := range ids {
		if overridden[id] {
			continue
		}
		c.add(&Use{Template: c.ctx.Catalog.TemplateByID(id), Kind: "template", Pos: included[id].Pos})
	}
}

func (c *collector) gitlabJob(job *model.Job) {
	env := knownEnv(job.Env)
	var main []model.Segment
	var sections []string
	var after *model.Script
	for _, sc := range job.Scripts {
		if sc.Section == "after_script" {
			after = sc
			continue
		}
		for range sc.Segments {
			sections = append(sections, sc.Section)
		}
		main = append(main, sc.Segments...)
	}
	run := func(segs []model.Segment, sectionOf func(line int) string, base int) {
		if len(segs) == 0 {
			return
		}
		opts := shell.GitLabOptions()
		opts.Env = env
		opts.Catalog = c.ctx.Catalog
		sm := newScriptMap(segs)
		res := shell.Analyze(sm.text, opts)
		for i, s := range res.Statements {
			c.event(job, Event{Order: base + i + 1, Group: base, Text: s.Text, Pos: sm.pos(s.Line, 1)})
		}
		for _, inv := range res.Invocations {
			c.cliUse(job, nil, sectionOf(sm.segmentOf(inv.Line)), inv, sm, base+inv.StmtIndex+1)
		}
	}
	run(main, func(i int) string {
		if i >= 0 && i < len(sections) {
			return sections[i]
		}
		return "script"
	}, 0)
	if after != nil {
		run(after.Segments, func(int) string { return "after_script" }, 1000000)
	}
}

// scriptMap joins segments into one script and maps script positions back
// to file positions.
type scriptMap struct {
	text  string
	lines []lineSrc
}

type lineSrc struct {
	pos     model.Pos // file position of the first column of the line
	segment int
}

func newScriptMap(segs []model.Segment) *scriptMap {
	sm := &scriptMap{}
	var b strings.Builder
	for si, s := range segs {
		t := strings.TrimSuffix(s.Text, "\n")
		for j := range strings.Split(t, "\n") {
			p := model.Pos{File: s.Pos.File, Line: s.Pos.Line + j, Column: s.Pos.Column}
			if j > 0 {
				p.Column = s.ContColumn
				if p.Column == 0 {
					p.Column = 1
				}
			}
			sm.lines = append(sm.lines, lineSrc{pos: p, segment: si})
		}
		b.WriteString(t)
		b.WriteString("\n")
	}
	sm.text = b.String()
	return sm
}

// pos maps a 1-based script line and column to a file position.
func (sm *scriptMap) pos(line, col int) model.Pos {
	if len(sm.lines) == 0 {
		return model.Pos{}
	}
	if line < 1 {
		line = 1
	}
	if line > len(sm.lines) {
		line = len(sm.lines)
	}
	l := sm.lines[line-1].pos
	if col < 1 {
		col = 1
	}
	l.Column += col - 1
	return l
}

func (sm *scriptMap) segmentOf(line int) int {
	if line < 1 || line > len(sm.lines) {
		return -1
	}
	return sm.lines[line-1].segment
}
