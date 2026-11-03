// Package github parses GitHub Actions workflow files and composite action
// metadata into the normalized pipeline model.
package github

import (
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/yamlutil"
)

// Parse parses a workflow file or an action metadata file (action.yml).
// Actions that are not composite are returned with no jobs.
func Parse(file string, data []byte) (*model.Pipeline, error) {
	doc, err := yamlutil.Parse(file, data)
	if err != nil {
		return nil, err
	}
	root, err := doc.RootMapping()
	if err != nil {
		return nil, err
	}
	p := &model.Pipeline{File: file, Platform: model.GitHub, Kind: "workflow", Files: []string{file}}
	if root == nil {
		return p, nil
	}
	if runs := yamlutil.Get(root, "runs"); runs != nil || IsActionFile(file) {
		p.Kind = "composite-action"
		parseAction(doc, root, p)
		return p, nil
	}
	parseWorkflow(doc, root, p)
	return p, nil
}

// IsActionFile reports whether a path names an action metadata file.
func IsActionFile(file string) bool {
	b := path.Base(strings.ReplaceAll(file, `\`, "/"))
	return b == "action.yml" || b == "action.yaml"
}

func envMap(doc *yamlutil.Doc, n *yaml.Node) map[string]model.Value {
	out := map[string]model.Value{}
	for _, pr := range yamlutil.Pairs(n) {
		v := yamlutil.Resolve(pr.Value)
		if v == nil || v.Kind != yaml.ScalarNode {
			continue
		}
		out[pr.Key.Value] = doc.Value(pr.Key, v)
	}
	return out
}

func value(doc *yamlutil.Doc, m *yaml.Node, key string) model.Value {
	pr, ok := yamlutil.GetPair(m, key)
	if !ok || pr.Value == nil {
		return model.Value{}
	}
	return doc.Value(pr.Key, pr.Value)
}

func defaultShell(doc *yamlutil.Doc, m *yaml.Node) model.Value {
	return value(doc, yamlutil.Get(yamlutil.Get(m, "defaults"), "run"), "shell")
}

func parseWorkflow(doc *yamlutil.Doc, root *yaml.Node, p *model.Pipeline) {
	p.Env = envMap(doc, yamlutil.Get(root, "env"))
	wfShell := defaultShell(doc, root)
	jobs := yamlutil.Get(root, "jobs")
	if jobs != nil && jobs.Kind != yaml.MappingNode {
		p.AddNote(doc.Pos(jobs), "jobs is not a mapping; nothing to scan")
		return
	}
	for _, pr := range yamlutil.Pairs(jobs) {
		jn := yamlutil.Resolve(pr.Value)
		if !yamlutil.IsMapping(jn) {
			continue
		}
		job := &model.Job{ID: pr.Key.Value, Name: pr.Key.Value, Pos: doc.Pos(pr.Key)}
		if n := yamlutil.Get(jn, "name"); yamlutil.IsScalar(n) && n.Value != "" {
			job.Name = n.Value
		}
		job.If = value(doc, jn, "if")
		job.ContinueOnError = value(doc, jn, "continue-on-error")
		job.Env = envMap(doc, yamlutil.Get(jn, "env"))
		job.RunsOn = runsOn(yamlutil.Get(jn, "runs-on"))
		job.Uses = value(doc, jn, "uses")
		job.DefaultShell = defaultShell(doc, jn)
		if !job.DefaultShell.Set {
			job.DefaultShell = wfShell
		}
		if job.Uses.Set {
			ref := strings.TrimSpace(job.Uses.Raw)
			if strings.HasPrefix(ref, "./") {
				p.LocalRefs = append(p.LocalRefs, strings.TrimPrefix(ref, "./"))
			} else {
				p.AddNote(job.Uses.Pos, "job %q calls the remote reusable workflow %s, which is out of scope", job.ID, ref)
			}
		}
		parseSteps(doc, yamlutil.Get(jn, "steps"), job, p)
		p.Jobs = append(p.Jobs, job)
	}
}

func runsOn(n *yaml.Node) string {
	n = yamlutil.Resolve(n)
	if n == nil {
		return ""
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value
	case yaml.SequenceNode:
		return strings.Join(yamlutil.StringList(n), ",")
	case yaml.MappingNode:
		var parts []string
		parts = append(parts, yamlutil.StringList(yamlutil.Get(n, "labels"))...)
		if g := yamlutil.Get(n, "group"); yamlutil.IsScalar(g) {
			parts = append(parts, g.Value)
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func parseSteps(doc *yamlutil.Doc, steps *yaml.Node, job *model.Job, p *model.Pipeline) {
	if steps == nil {
		return
	}
	if steps.Kind != yaml.SequenceNode {
		p.AddNote(doc.Pos(steps), "steps of job %q is not a list; skipped", job.ID)
		return
	}
	for i, item := range steps.Content {
		sn := yamlutil.Resolve(item)
		if !yamlutil.IsMapping(sn) {
			continue
		}
		st := &model.Step{Index: i, Pos: doc.Pos(sn)}
		st.Uses = value(doc, sn, "uses")
		st.If = value(doc, sn, "if")
		st.ContinueOnError = value(doc, sn, "continue-on-error")
		st.Shell = value(doc, sn, "shell")
		st.Env = envMap(doc, yamlutil.Get(sn, "env"))
		for _, pr := range yamlutil.Pairs(yamlutil.Get(sn, "with")) {
			v := yamlutil.Resolve(pr.Value)
			if v == nil {
				continue
			}
			mv := doc.Value(pr.Key, v)
			// Report inputs at the value so multi-line args point at the text.
			if v.Kind == yaml.ScalarNode && (v.Style == yaml.LiteralStyle || v.Style == yaml.FoldedStyle) {
				mv.Pos = doc.Pos(pr.Key)
			}
			st.With = append(st.With, model.Input{Name: pr.Key.Value, Value: mv})
		}
		if run := yamlutil.Get(sn, "run"); yamlutil.IsScalar(run) {
			st.Run = &model.Script{Section: "run", Segments: []model.Segment{doc.Segment(run)}}
		}
		st.Name = stepName(sn, st, i)
		if st.Uses.Set {
			ref := strings.TrimSpace(st.Uses.Raw)
			if strings.HasPrefix(ref, "./") {
				p.LocalRefs = append(p.LocalRefs, strings.TrimSuffix(strings.TrimPrefix(ref, "./"), "/"))
			}
		}
		job.Steps = append(job.Steps, st)
	}
}

func stepName(sn *yaml.Node, st *model.Step, i int) string {
	if n := yamlutil.Get(sn, "name"); yamlutil.IsScalar(n) && strings.TrimSpace(n.Value) != "" {
		return strings.TrimSpace(n.Value)
	}
	if n := yamlutil.Get(sn, "id"); yamlutil.IsScalar(n) && n.Value != "" {
		return n.Value
	}
	if st.Uses.Set {
		return st.Uses.Raw
	}
	if st.Run != nil {
		first := strings.TrimSpace(strings.SplitN(strings.TrimSpace(st.Run.Segments[0].Text), "\n", 2)[0])
		if len(first) > 40 {
			first = first[:37] + "..."
		}
		if first != "" {
			return "run: " + first
		}
	}
	return fmt.Sprintf("step %d", i+1)
}

func parseAction(doc *yamlutil.Doc, root *yaml.Node, p *model.Pipeline) {
	runs := yamlutil.Get(root, "runs")
	using := strings.ToLower(yamlutil.ScalarString(yamlutil.Get(runs, "using")))
	if using != "composite" {
		return
	}
	name := "composite action"
	if n := yamlutil.Get(root, "name"); yamlutil.IsScalar(n) && n.Value != "" {
		name = n.Value
	}
	job := &model.Job{ID: name, Name: name, Pos: doc.Pos(runs)}
	parseSteps(doc, yamlutil.Get(runs, "steps"), job, p)
	p.Jobs = append(p.Jobs, job)
}
