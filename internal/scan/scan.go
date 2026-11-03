// Package scan ties gatelint together: it discovers CI files, parses them,
// runs the rules, applies suppressions and builds the coverage summary.
package scan

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
	"github.com/codewithQasimAli/gatelint/internal/github"
	"github.com/codewithQasimAli/gatelint/internal/gitlab"
	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/rules"
	"github.com/codewithQasimAli/gatelint/internal/suppress"
)

// Options configure a scan.
type Options struct {
	// Platform is "auto", "github" or "gitlab".
	Platform string
	// Config is an explicit configuration; when nil, .gatelint.yml is
	// looked up in the first scanned directory.
	Config *Config
	// NoAutoConfig disables the configuration lookup.
	NoAutoConfig bool
	// Cwd is the directory display paths are relative to; it defaults to
	// the process working directory.
	Cwd string
}

type kind int

const (
	kindWorkflow kind = iota + 1
	kindAction
	kindGitLab
)

type candidate struct {
	fsPath  string
	display string
	kind    kind
	root    string
}

type scanner struct {
	opts    Options
	cat     *catalog.Catalog
	exclude excluder
	seen    map[string]bool
	queue   []candidate
	data    map[string][]byte
	res     *model.Result
	pipes   []*model.Pipeline
}

// Run scans the given paths. Problems with individual files are reported in
// Result.Errors; the error return is reserved for unusable input such as a
// path that does not exist.
func Run(paths []string, opts Options) (*model.Result, *Config, error) {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	if opts.Cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, nil, err
		}
		opts.Cwd = wd
	}
	switch opts.Platform {
	case "", "auto", "github", "gitlab":
	default:
		return nil, nil, fmt.Errorf("unknown platform %q (want auto, github or gitlab)", opts.Platform)
	}
	cfg := opts.Config
	if cfg == nil && !opts.NoAutoConfig {
		dir := paths[0]
		if st, err := os.Stat(dir); err == nil && !st.IsDir() {
			dir = filepath.Dir(dir)
		}
		if p := FindConfig(dir); p != "" {
			c, err := LoadConfig(p)
			if err != nil {
				return nil, nil, err
			}
			cfg = c
		}
	}
	if cfg == nil {
		cfg = &Config{}
	}
	s := &scanner{
		opts:    opts,
		cat:     catalog.Default().Merge(&catalog.Catalog{Tools: cfg.Scanners, Templates: cfg.GitLabTemplates}),
		exclude: newExcluder(cfg.Exclude),
		seen:    map[string]bool{},
		data:    map[string][]byte{},
		res:     &model.Result{},
	}
	for _, p := range paths {
		if err := s.discover(p); err != nil {
			return nil, nil, err
		}
	}
	s.process()

	disabled := map[string]bool{}
	for _, id := range cfg.DisableRules {
		disabled[strings.ToUpper(id)] = true
	}
	ctx := &rules.Context{Catalog: s.cat, Pipelines: s.pipes, Directives: map[string][]suppress.Directive{}, Disabled: disabled}
	for _, f := range s.res.Files {
		if d := suppress.Parse(f, s.data[f]); len(d) > 0 {
			ctx.Directives[f] = d
		}
	}
	rules.Collect(ctx, repoFiles)
	findings := rules.Run(ctx)
	suppress.Apply(findings, ctx.Directives, rules.Exempt)
	s.res.Findings = findings
	s.res.Coverage = rules.Coverage(ctx, findings, s.res.Files)
	for _, p := range s.pipes {
		s.res.Notes = append(s.res.Notes, p.Notes...)
	}
	sort.SliceStable(s.res.Notes, func(i, j int) bool {
		a, b := s.res.Notes[i], s.res.Notes[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	if s.res.Findings == nil {
		s.res.Findings = []model.Finding{}
	}
	return s.res, cfg, nil
}

func repoFiles(p *model.Pipeline, name string) bool {
	if p.Root == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(p.Root, filepath.FromSlash(name)))
	return err == nil && !st.IsDir()
}

func (s *scanner) display(fsPath string) string {
	abs, err := filepath.Abs(fsPath)
	if err != nil {
		return filepath.ToSlash(fsPath)
	}
	if rel, err := filepath.Rel(s.opts.Cwd, abs); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(abs)
}

func (s *scanner) wants(k kind) bool {
	switch s.opts.Platform {
	case "github":
		return k == kindWorkflow || k == kindAction
	case "gitlab":
		return k == kindGitLab
	}
	return true
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "testdata": true, ".venv": true, "venv": true}

func (s *scanner) discover(p string) error {
	st, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("cannot scan %s: %w", p, err)
	}
	if !st.IsDir() {
		k := s.detect(p)
		if k == 0 {
			return fmt.Errorf("cannot tell whether %s is a GitHub or GitLab file; use --platform", p)
		}
		s.enqueue(p, k)
		return nil
	}
	return filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.res.Errors = append(s.res.Errors, model.FileError{File: s.display(path), Message: err.Error()})
			return nil
		}
		if d.IsDir() {
			if path != p && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if path != p && s.exclude.match(s.display(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if k := classify(path); k != 0 {
			s.enqueue(path, k)
		}
		return nil
	})
}

// classify recognises CI files by their location and name.
func classify(path string) kind {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	dir := filepath.Base(filepath.Dir(path))
	parent := filepath.Base(filepath.Dir(filepath.Dir(path)))
	switch {
	case (ext == ".yml" || ext == ".yaml") && dir == "workflows" && parent == ".github":
		return kindWorkflow
	case base == "action.yml" || base == "action.yaml":
		return kindAction
	case base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml":
		return kindGitLab
	}
	return 0
}

// detect classifies an explicitly named file, falling back to --platform
// and finally to the file's contents.
func (s *scanner) detect(path string) kind {
	if k := classify(path); k != 0 {
		return k
	}
	switch s.opts.Platform {
	case "github":
		return kindWorkflow
	case "gitlab":
		return kindGitLab
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return kindGitLab
	}
	if bytes.Contains(data, []byte("runs-on:")) || (bytes.Contains(data, []byte("\njobs:")) && bytes.Contains(data, []byte("steps:"))) {
		return kindWorkflow
	}
	if bytes.Contains(data, []byte("\nruns:")) || bytes.HasPrefix(data, []byte("runs:")) {
		return kindAction
	}
	if bytes.Contains(data, []byte("script:")) || bytes.Contains(data, []byte("stages:")) {
		return kindGitLab
	}
	return 0
}

func (s *scanner) enqueue(path string, k kind) {
	if !s.wants(k) {
		return
	}
	disp := s.display(path)
	if s.seen[disp] || s.exclude.match(disp) {
		return
	}
	s.seen[disp] = true
	s.queue = append(s.queue, candidate{fsPath: path, display: disp, kind: k, root: findRoot(path, k)})
}

// findRoot returns the repository root a CI file belongs to.
func findRoot(path string, k kind) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	dir := filepath.Dir(abs)
	switch k {
	case kindWorkflow:
		return filepath.Dir(filepath.Dir(dir))
	case kindGitLab:
		return dir
	}
	for d := dir; ; d = filepath.Dir(d) {
		if st, err := os.Stat(filepath.Join(d, ".github")); err == nil && st.IsDir() {
			return d
		}
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil && st.IsDir() {
			return d
		}
		if filepath.Dir(d) == d {
			return dir
		}
	}
}

func (s *scanner) process() {
	for i := 0; i < len(s.queue); i++ {
		c := s.queue[i]
		data, err := os.ReadFile(c.fsPath)
		if err != nil {
			s.res.Errors = append(s.res.Errors, model.FileError{File: c.display, Message: err.Error()})
			continue
		}
		s.data[c.display] = data
		var p *model.Pipeline
		switch c.kind {
		case kindWorkflow, kindAction:
			p, err = github.Parse(c.display, data)
		case kindGitLab:
			p, err = gitlab.Parse(c.display, data, gitlab.Options{
				Root:    c.root,
				Display: s.display,
				ReadFile: func(name string) ([]byte, error) {
					b, err := os.ReadFile(name)
					if err == nil {
						s.data[s.display(name)] = b
					}
					return b, err
				},
			})
		}
		if err != nil {
			s.res.Errors = append(s.res.Errors, model.FileError{File: c.display, Message: err.Error()})
			continue
		}
		p.Root = c.root
		if c.kind == kindAction && len(p.Jobs) == 0 {
			// Docker and JavaScript actions have no steps to check.
			s.res.Files = append(s.res.Files, c.display)
			continue
		}
		s.res.Files = append(s.res.Files, p.Files...)
		for _, f := range p.Files[1:] {
			s.seen[f] = true
		}
		s.pipes = append(s.pipes, p)
		s.followRefs(p)
	}
	sort.Strings(s.res.Files)
	s.res.Files = dedupe(s.res.Files)
}

// followRefs queues local reusable workflows and actions referenced by a
// GitHub pipeline.
func (s *scanner) followRefs(p *model.Pipeline) {
	if p.Platform != model.GitHub {
		return
	}
	for _, ref := range p.LocalRefs {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(ref)))
		if clean == ".." || strings.HasPrefix(clean, "../") {
			p.AddNote(model.Pos{File: p.File}, "local reference ./%s points outside the repository and was not followed", ref)
			continue
		}
		target := filepath.Join(p.Root, filepath.FromSlash(ref))
		st, err := os.Stat(target)
		if err != nil {
			p.AddNote(model.Pos{File: p.File}, "local reference ./%s was not found", ref)
			continue
		}
		if st.IsDir() {
			found := false
			for _, n := range []string{"action.yml", "action.yaml"} {
				if f := filepath.Join(target, n); fileExists(f) {
					s.enqueue(f, kindAction)
					found = true
					break
				}
			}
			if !found {
				p.AddNote(model.Pos{File: p.File}, "local action ./%s has no action.yml", ref)
			}
			continue
		}
		s.enqueue(target, kindWorkflow)
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if len(out) > 0 && out[len(out)-1] == x {
			continue
		}
		out = append(out, x)
	}
	return out
}
