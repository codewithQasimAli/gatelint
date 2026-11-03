// Package gitlab parses .gitlab-ci.yml files, including local includes,
// YAML anchors and aliases, extends: and !reference tags, into the
// normalized pipeline model.
package gitlab

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/yamlutil"
)

// maxIncludes mirrors GitLab's limit on the number of included files.
const maxIncludes = 150

// Options configure how includes are resolved.
type Options struct {
	// Root is the repository root that local includes resolve against.
	Root string
	// Display converts a filesystem path into the path used in reports.
	Display func(fsPath string) string
	// ReadFile reads an included file; it defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
}

// securityReportKinds are artifacts:reports types shown in merge requests.
var securityReportKinds = []string{"sast", "secret_detection", "dependency_scanning", "container_scanning", "dast", "api_fuzzing", "coverage_fuzzing", "codequality"}

var reserved = map[string]bool{
	"default": true, "include": true, "stages": true, "variables": true, "workflow": true,
	"image": true, "services": true, "cache": true, "before_script": true, "after_script": true,
	"types": true, "spec": true,
}

type parser struct {
	opts     Options
	p        *model.Pipeline
	top      *mval
	resolved map[string]*mval
	visiting map[string]bool
	loaded   map[string]bool
	includes int
}

// Parse parses a GitLab CI configuration. file is the display path of the
// main configuration file.
func Parse(file string, data []byte, opts Options) (*model.Pipeline, error) {
	if opts.ReadFile == nil {
		opts.ReadFile = os.ReadFile
	}
	if opts.Display == nil {
		opts.Display = func(s string) string { return filepath.ToSlash(s) }
	}
	ps := &parser{
		opts:     opts,
		p:        &model.Pipeline{File: file, Platform: model.GitLab, Kind: "gitlab-ci", Files: []string{file}, Root: opts.Root},
		resolved: map[string]*mval{},
		visiting: map[string]bool{},
		loaded:   map[string]bool{file: true},
	}
	top, err := ps.load(file, data, 0)
	if err != nil {
		return nil, err
	}
	ps.top = top
	ps.build()
	return ps.p, nil
}

// load parses one file and merges its local includes underneath it.
func (ps *parser) load(file string, data []byte, depth int) (*mval, error) {
	doc, err := yamlutil.Parse(file, data)
	if err != nil {
		return nil, err
	}
	root, err := doc.RootMapping()
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	top := fromNode(doc, nil, root, 0)
	var base *mval
	if inc := top.get("include"); inc != nil {
		base = ps.includes1(inc, depth)
	}
	return merge(base, top), nil
}

func (ps *parser) includes1(inc *mval, depth int) *mval {
	var base *mval
	n := inc.node
	var items []*yaml.Node
	if n.Kind == yaml.SequenceNode {
		items = n.Content
	} else {
		items = []*yaml.Node{n}
	}
	for _, it := range items {
		it = yamlutil.Resolve(it)
		if it == nil {
			continue
		}
		pos := inc.doc.Pos(it)
		switch it.Kind {
		case yaml.ScalarNode:
			v := strings.TrimSpace(it.Value)
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				ps.p.AddNote(pos, "remote include %s is out of scope", v)
				continue
			}
			base = merge(base, ps.local(v, pos, depth))
		case yaml.MappingNode:
			switch {
			case yamlutil.Get(it, "local") != nil:
				base = merge(base, ps.local(yamlutil.ScalarString(yamlutil.Get(it, "local")), pos, depth))
			case yamlutil.Get(it, "template") != nil:
				ps.p.Templates = append(ps.p.Templates, model.TemplateUse{Name: yamlutil.ScalarString(yamlutil.Get(it, "template")), Pos: pos})
			case yamlutil.Get(it, "component") != nil:
				ps.p.Templates = append(ps.p.Templates, model.TemplateUse{Name: yamlutil.ScalarString(yamlutil.Get(it, "component")), Pos: pos})
			case yamlutil.Get(it, "project") != nil:
				ps.p.AddNote(pos, "include from project %s is out of scope", yamlutil.ScalarString(yamlutil.Get(it, "project")))
			case yamlutil.Get(it, "remote") != nil:
				ps.p.AddNote(pos, "remote include %s is out of scope", yamlutil.ScalarString(yamlutil.Get(it, "remote")))
			}
		}
	}
	return base
}

// local loads a local include, which may be a glob.
func (ps *parser) local(pattern string, pos model.Pos, depth int) *mval {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	if strings.Contains(pattern, "$") {
		ps.p.AddNote(pos, "local include %s uses variables and was not resolved", pattern)
		return nil
	}
	if depth >= maxDepth {
		ps.p.AddNote(pos, "include nesting is too deep; %s not loaded", pattern)
		return nil
	}
	rel := strings.TrimPrefix(pattern, "/")
	if escapesRoot(rel) {
		ps.p.AddNote(pos, "local include %s points outside the repository and was not loaded", pattern)
		return nil
	}
	matches := ps.glob(rel)
	if len(matches) == 0 {
		ps.p.AddNote(pos, "local include %s was not found", pattern)
		return nil
	}
	var base *mval
	for _, fsPath := range matches {
		display := ps.opts.Display(fsPath)
		if ps.loaded[display] {
			continue
		}
		ps.loaded[display] = true
		ps.includes++
		if ps.includes > maxIncludes {
			ps.p.AddNote(pos, "more than %d includes; the rest were not loaded", maxIncludes)
			return base
		}
		data, err := ps.opts.ReadFile(fsPath)
		if err != nil {
			ps.p.AddNote(pos, "local include %s could not be read: %v", pattern, err)
			continue
		}
		v, err := ps.load(display, data, depth+1)
		if err != nil {
			ps.p.AddNote(pos, "local include %s: %v", display, err)
			continue
		}
		ps.p.Files = append(ps.p.Files, display)
		base = merge(base, v)
	}
	return base
}

func (ps *parser) glob(pattern string) []string {
	root := ps.opts.Root
	if !strings.ContainsAny(pattern, "*?[") {
		p := filepath.Join(root, filepath.FromSlash(pattern))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return []string{p}
		}
		return nil
	}
	re := globRegexp(pattern)
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr == nil && re.MatchString(filepath.ToSlash(rel)) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// escapesRoot reports whether a repository-relative path leaves the root.
func escapesRoot(rel string) bool {
	c := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	return c == ".." || strings.HasPrefix(c, "../") || filepath.IsAbs(filepath.FromSlash(rel))
}

// globRegexp converts a GitLab include glob ("*" within a directory, "**"
// across directories) into a regular expression.
func globRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
			if i+1 < len(pattern) && pattern[i+1] == '/' {
				b.WriteString("/?")
				i++
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func (ps *parser) build() {
	top := ps.top
	if top == nil {
		return
	}
	ps.p.Env = variables(top.get("variables"))
	def := top.get("default")
	for _, name := range top.keys {
		if reserved[name] || strings.HasPrefix(name, ".") {
			continue
		}
		raw := top.m[name]
		if !raw.isMap() {
			continue
		}
		jv := ps.resolve(name, 0)
		if jv == nil {
			continue
		}
		if jv.get("trigger") != nil {
			continue
		}
		ps.p.Jobs = append(ps.p.Jobs, ps.job(name, raw, jv, def))
	}
}

// resolve returns a job (or hidden job) with extends: applied.
func (ps *parser) resolve(name string, depth int) *mval {
	if v, ok := ps.resolved[name]; ok {
		return v
	}
	raw := ps.top.get(name)
	if !raw.isMap() {
		return nil
	}
	if ps.visiting[name] || depth > maxDepth {
		ps.p.AddNote(ps.pos(raw), "extends chain of %q is cyclic or too deep; not fully resolved", name)
		return raw.without("extends")
	}
	ps.visiting[name] = true
	defer delete(ps.visiting, name)
	var base *mval
	if ext := raw.get("extends"); ext != nil {
		for _, parent := range yamlutil.StringList(ext.node) {
			pv := ps.resolve(parent, depth+1)
			if pv == nil {
				ps.p.AddNote(ps.pos(ext), "job %q extends unknown job %q; partial result", name, parent)
				continue
			}
			base = merge(base, pv)
		}
	}
	out := merge(base, raw.without("extends"))
	ps.resolved[name] = out
	return out
}

func (ps *parser) pos(v *mval) model.Pos {
	if v == nil {
		return model.Pos{File: ps.p.File}
	}
	if v.key != nil {
		return v.doc.Pos(v.key)
	}
	return v.doc.Pos(v.node)
}

func (ps *parser) job(name string, raw, jv, def *mval) *model.Job {
	job := &model.Job{ID: name, Name: name, Pos: ps.pos(raw)}
	inheritDefault, inheritVars := inherit(jv.get("inherit"))
	job.Env = map[string]model.Value{}
	if inheritVars {
		for k, v := range ps.p.Env {
			job.Env[k] = v
		}
	}
	for k, v := range variables(jv.get("variables")) {
		job.Env[k] = v
	}
	if img := jv.get("image"); img != nil {
		job.Image = imageName(img)
	} else if inheritDefault("image") {
		if img := def.get("image"); img != nil {
			job.Image = imageName(img)
		} else if img := ps.top.get("image"); img != nil {
			job.Image = imageName(img)
		}
	}
	section := func(key string) *mval {
		if v := jv.get(key); v != nil {
			return v
		}
		if !inheritDefault(key) {
			return nil
		}
		if v := def.get(key); v != nil {
			return v
		}
		return ps.top.get(key)
	}
	for _, key := range []string{"before_script", "script", "after_script"} {
		v := section(key)
		if v == nil {
			continue
		}
		sc := &model.Script{Section: key}
		for _, item := range ps.flatten(v, name, 0) {
			if item.node.Kind == yaml.ScalarNode && item.node.Tag != "!!null" {
				sc.Segments = append(sc.Segments, item.doc.Segment(item.node))
			}
		}
		if len(sc.Segments) > 0 {
			job.Scripts = append(job.Scripts, sc)
		}
	}
	for _, kind := range securityReportKinds {
		if r := jv.get("artifacts").get("reports").get(kind); r != nil {
			job.SecurityReports = append(job.SecurityReports, yamlutil.StringList(r.node)...)
		}
	}
	if v := jv.get("when"); v != nil {
		job.When = mvalue(v)
	}
	if v := jv.get("allow_failure"); v != nil {
		job.AllowFailure = allowFailure(v)
	}
	if v := jv.get("rules"); v != nil {
		for _, item := range ps.flatten(v, name, 0) {
			if item.node.Kind != yaml.MappingNode {
				continue
			}
			rv := fromNode(item.doc, nil, item.node, 0)
			re := model.RuleEntry{Pos: item.doc.Pos(item.node)}
			if w := rv.get("when"); w != nil {
				re.When = mvalue(w)
			}
			if c := rv.get("if"); c != nil {
				re.If = yamlutil.ScalarString(c.node)
			}
			if af := rv.get("allow_failure"); af != nil {
				re.AllowFailure = allowFailure(af)
			}
			job.Rules = append(job.Rules, re)
		}
	}
	return job
}

// flatten expands a script or rules value into its scalar or mapping items,
// following nested sequences and !reference tags.
func (ps *parser) flatten(v *mval, job string, depth int) []*mval {
	if v == nil || depth > maxDepth {
		return nil
	}
	n := v.node
	if n.Tag == "!reference" {
		ref := ps.reference(v, job)
		if ref == nil {
			return nil
		}
		return ps.flatten(ref, job, depth+1)
	}
	if n.Kind != yaml.SequenceNode {
		return []*mval{v}
	}
	var out []*mval
	for _, c := range n.Content {
		c = yamlutil.Resolve(c)
		if c == nil {
			continue
		}
		out = append(out, ps.flatten(&mval{doc: v.doc, node: c}, job, depth+1)...)
	}
	return out
}

// reference resolves a !reference [job, key, ...] tag against the merged
// configuration. Unresolvable references produce a note and are skipped.
func (ps *parser) reference(v *mval, job string) *mval {
	parts := yamlutil.StringList(v.node)
	pos := v.doc.Pos(v.node)
	if len(parts) < 2 {
		ps.p.AddNote(pos, "!reference in job %q is malformed and was not resolved; partial result", job)
		return nil
	}
	cur := ps.resolve(parts[0], 0)
	if cur == nil {
		cur = ps.top.get(parts[0])
	}
	for _, k := range parts[1:] {
		cur = cur.get(k)
	}
	if cur == nil {
		ps.p.AddNote(pos, "!reference [%s] in job %q could not be resolved; partial result", strings.Join(parts, ", "), job)
		return nil
	}
	return cur
}

func mvalue(v *mval) model.Value {
	return v.doc.Value(v.key, v.node)
}

func imageName(v *mval) string {
	if v.isMap() {
		if n := v.get("name"); n != nil {
			return yamlutil.ScalarString(n.node)
		}
		return ""
	}
	return yamlutil.ScalarString(v.node)
}

func variables(v *mval) map[string]model.Value {
	out := map[string]model.Value{}
	if !v.isMap() {
		return out
	}
	for _, k := range v.keys {
		item := v.m[k]
		if item == nil {
			continue
		}
		if item.isMap() {
			if val := item.get("value"); val != nil {
				mv := val.doc.Value(item.key, val.node)
				out[k] = mv
			}
			continue
		}
		if item.node.Kind == yaml.ScalarNode {
			out[k] = item.doc.Value(item.key, item.node)
		}
	}
	return out
}

func allowFailure(v *mval) model.AllowFailure {
	af := model.AllowFailure{Set: true, Pos: v.doc.Pos(v.key)}
	if v.key == nil {
		af.Pos = v.doc.Pos(v.node)
	}
	if v.isMap() {
		af.Raw = "exit_codes"
		if ec := v.get("exit_codes"); ec != nil {
			for _, s := range yamlutil.StringList(ec.node) {
				if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
					af.ExitCodes = append(af.ExitCodes, n)
				}
			}
			af.Raw = fmt.Sprintf("exit_codes %v", af.ExitCodes)
		}
		return af
	}
	af.Raw = yamlutil.ScalarString(v.node)
	af.Bool = strings.EqualFold(strings.TrimSpace(af.Raw), "true")
	return af
}

// inherit interprets the inherit: keyword. It returns a predicate telling
// whether a given default: keyword is inherited, and whether global
// variables are inherited.
func inherit(v *mval) (func(string) bool, bool) {
	all := func(string) bool { return true }
	if !v.isMap() {
		return all, true
	}
	defFn := all
	if d := v.get("default"); d != nil {
		switch d.node.Kind {
		case yaml.ScalarNode:
			if strings.EqualFold(d.node.Value, "false") {
				defFn = func(string) bool { return false }
			}
		case yaml.SequenceNode:
			allowed := map[string]bool{}
			for _, s := range yamlutil.StringList(d.node) {
				allowed[s] = true
			}
			defFn = func(k string) bool { return allowed[k] }
		}
	}
	vars := true
	if d := v.get("variables"); d != nil && d.node.Kind == yaml.ScalarNode && strings.EqualFold(d.node.Value, "false") {
		vars = false
	}
	return defFn, vars
}
