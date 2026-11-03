// Package catalog describes the security scanners gatelint understands: how
// they are invoked, whether they fail a build by default, and which flags or
// action inputs turn the gate on or off. The built-in catalog is embedded as
// YAML and can be extended or overridden from a project configuration file.
package catalog

import (
	_ "embed"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default.yml
var defaultCatalog []byte

// Condition names a predicate on a flag or input value.
type Condition string

// Supported conditions.
const (
	// CondSet matches a boolean flag that is present (and not "=false").
	CondSet Condition = "set"
	// CondZero matches a numeric value equal to zero.
	CondZero Condition = "zero"
	// CondNonZero matches a numeric value other than zero.
	CondNonZero Condition = "nonzero"
	// CondAny matches any non-empty value.
	CondAny Condition = "any"
	// CondTrue matches "true" (case-insensitive) or "1".
	CondTrue Condition = "true"
	// CondFalse matches "false" (case-insensitive) or "0".
	CondFalse Condition = "false"
)

// Setting is a command-line flag (or environment variable, or action input)
// that changes whether a scanner gates.
type Setting struct {
	Names []string `yaml:"names"`
	Env   string   `yaml:"env"`
	// TakesValue is true for flags of the form --flag VALUE.
	TakesValue bool `yaml:"takes-value"`
	// GateWhen and NeuterWhen are conditions on the value.
	GateWhen   Condition `yaml:"gate-when"`
	NeuterWhen Condition `yaml:"neuter-when"`
	// NeuterValues neuters when the value equals one of these.
	NeuterValues []string `yaml:"neuter-values"`
	// ExitCode marks a setting whose value is the exit code used on failure.
	ExitCode bool   `yaml:"exit-code"`
	Desc     string `yaml:"description"`
	// Example shows how to turn the gate on, for fix hints.
	Example string `yaml:"example"`
}

// Mode is a sub-command family with its own gating behaviour.
type Mode struct {
	Subcommands    []string  `yaml:"subcommands"`
	GatesByDefault bool      `yaml:"gates-by-default"`
	NeverGates     bool      `yaml:"never-gates"`
	Settings       []Setting `yaml:"settings"`
	Note           string    `yaml:"note"`
}

// Action describes a GitHub Action (or a family of actions sharing a prefix)
// that runs the scanner.
type Action struct {
	Uses           string    `yaml:"uses"`
	Prefix         bool      `yaml:"prefix"`
	GatesByDefault bool      `yaml:"gates-by-default"`
	InfoOnly       bool      `yaml:"info-only"`
	Inputs         []Setting `yaml:"inputs"`
	ConfigInputs   []string  `yaml:"config-inputs"`
	OutputInputs   []string  `yaml:"output-inputs"`
	// ArgsInput names an input holding extra CLI arguments that are
	// evaluated with the tool's flag settings.
	ArgsInput string `yaml:"args-input"`
	// CommandInput names an input selecting the tool sub-command.
	CommandInput   string `yaml:"command-input"`
	DefaultCommand string `yaml:"default-command"`
	// HonourEnv applies the tool's env-based settings from the step env.
	HonourEnv bool   `yaml:"honour-env"`
	Note      string `yaml:"note"`
}

// Tool is one scanner.
type Tool struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	// Commands are command words, e.g. "trivy" or "npm audit".
	Commands      []string `yaml:"commands"`
	PythonModules []string `yaml:"python-modules"`
	Packages      []string `yaml:"packages"`
	Images        []string `yaml:"images"`
	// SkipFlags and SkipSubcommands mark invocations that do not scan,
	// such as --version.
	SkipFlags       []string `yaml:"skip-flags"`
	SkipSubcommands []string `yaml:"skip-subcommands"`
	ConfigFlags     []string `yaml:"config-flags"`
	// DefaultConfigFiles are read automatically from the working directory
	// and may change the exit code, so their presence makes the gating
	// status indeterminate.
	DefaultConfigFiles []string  `yaml:"default-config-files"`
	OutputFlags        []string  `yaml:"output-flags"`
	FailExitCodes      []int     `yaml:"fail-exit-codes"`
	Settings           []Setting `yaml:"settings"`
	Modes              []Mode    `yaml:"modes"`
	Actions            []Action  `yaml:"actions"`
	InfoOnly           bool      `yaml:"info-only"`
	Note               string    `yaml:"note"`
}

// GitLabTemplate describes a GitLab-provided security template.
type GitLabTemplate struct {
	ID               string   `yaml:"id"`
	Name             string   `yaml:"name"`
	Templates        []string `yaml:"templates"`
	Components       []string `yaml:"components"`
	DisableVariables []string `yaml:"disable-variables"`
	Jobs             []string `yaml:"jobs"`
	Note             string   `yaml:"note"`
}

// Catalog is the set of known scanners.
type Catalog struct {
	Tools     []*Tool           `yaml:"scanners"`
	Templates []*GitLabTemplate `yaml:"gitlab-templates"`
}

// Default returns the built-in catalog.
func Default() *Catalog {
	c, err := Parse(defaultCatalog)
	if err != nil {
		panic("catalog: built-in catalog is invalid: " + err.Error())
	}
	return c
}

// Parse decodes a catalog document.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

var validConditions = map[Condition]bool{
	"": true, CondSet: true, CondZero: true, CondNonZero: true, CondAny: true, CondTrue: true, CondFalse: true,
}

// Validate checks the catalog for structural errors.
func (c *Catalog) Validate() error {
	var errs []error
	seen := map[string]bool{}
	checkSettings := func(id string, ss []Setting) {
		for _, s := range ss {
			if len(s.Names) == 0 && s.Env == "" {
				errs = append(errs, fmt.Errorf("scanner %q: setting needs names or env", id))
			}
			if !validConditions[s.GateWhen] || !validConditions[s.NeuterWhen] {
				errs = append(errs, fmt.Errorf("scanner %q: setting %v has an unknown condition", id, s.Names))
			}
		}
	}
	for _, t := range c.Tools {
		if t.ID == "" {
			errs = append(errs, errors.New("scanner without id"))
			continue
		}
		if seen[t.ID] {
			errs = append(errs, fmt.Errorf("duplicate scanner id %q", t.ID))
		}
		seen[t.ID] = true
		if t.Name == "" {
			t.Name = t.ID
		}
		if len(t.Commands)+len(t.PythonModules)+len(t.Packages)+len(t.Images)+len(t.Actions) == 0 {
			errs = append(errs, fmt.Errorf("scanner %q: needs at least one of commands, python-modules, packages, images or actions", t.ID))
		}
		checkSettings(t.ID, t.Settings)
		for _, m := range t.Modes {
			checkSettings(t.ID, m.Settings)
		}
		for _, a := range t.Actions {
			if a.Uses == "" {
				errs = append(errs, fmt.Errorf("scanner %q: action without uses", t.ID))
			}
			checkSettings(t.ID, a.Inputs)
		}
		if len(t.FailExitCodes) == 0 {
			t.FailExitCodes = []int{1}
		}
	}
	for _, tpl := range c.Templates {
		if tpl.ID == "" {
			errs = append(errs, errors.New("gitlab template without id"))
		}
	}
	return errors.Join(errs...)
}

// Merge returns a copy of c with entries from other added; entries with the
// same ID replace the built-in ones.
func (c *Catalog) Merge(other *Catalog) *Catalog {
	out := &Catalog{}
	byID := map[string]int{}
	for _, t := range c.Tools {
		byID[t.ID] = len(out.Tools)
		out.Tools = append(out.Tools, t)
	}
	if other != nil {
		for _, t := range other.Tools {
			if i, ok := byID[t.ID]; ok {
				out.Tools[i] = t
				continue
			}
			byID[t.ID] = len(out.Tools)
			out.Tools = append(out.Tools, t)
		}
	}
	tplByID := map[string]int{}
	for _, t := range c.Templates {
		tplByID[t.ID] = len(out.Templates)
		out.Templates = append(out.Templates, t)
	}
	if other != nil {
		for _, t := range other.Templates {
			if i, ok := tplByID[t.ID]; ok {
				out.Templates[i] = t
				continue
			}
			out.Templates = append(out.Templates, t)
		}
	}
	return out
}

// GateExample returns the example of the first setting that turns the gate
// on for the given mode (or action), or "".
func (t *Tool) GateExample(m *Mode, a *Action) string {
	if a != nil {
		for _, s := range a.Inputs {
			if s.GateWhen != "" && s.Example != "" {
				return s.Example
			}
		}
		if a.ArgsInput == "" {
			return ""
		}
	}
	for _, s := range t.settings(m) {
		if s.GateWhen != "" && s.Example != "" {
			return s.Example
		}
	}
	return ""
}

// Tool returns the scanner with the given ID.
func (c *Catalog) Tool(id string) *Tool {
	for _, t := range c.Tools {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// Names returns the display names of all scanners, sorted.
func (c *Catalog) Names() []string {
	var out []string
	for _, t := range c.Tools {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

// Action finds the catalog entry for a "uses:" reference such as
// "aquasecurity/trivy-action@0.28.0".
func (c *Catalog) Action(uses string) (*Tool, *Action) {
	ref := strings.ToLower(strings.TrimSpace(uses))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	ref = strings.TrimSuffix(ref, "/")
	for _, t := range c.Tools {
		for i := range t.Actions {
			a := &t.Actions[i]
			want := strings.ToLower(a.Uses)
			if ref == want || (a.Prefix && strings.HasPrefix(ref, want+"/")) {
				return t, a
			}
		}
	}
	return nil, nil
}

// NormalizeImage strips registry defaults, tags and digests from an image
// reference so it can be compared with catalog entries.
func NormalizeImage(image string) string {
	img := strings.ToLower(strings.TrimSpace(image))
	img = strings.TrimPrefix(img, "docker://")
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	// A tag follows the last colon that comes after the last slash.
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		img = img[:i]
	}
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		img = strings.TrimPrefix(img, p)
	}
	return strings.TrimPrefix(img, "library/")
}

// Image finds the scanner whose container image matches image.
func (c *Catalog) Image(image string) *Tool {
	img := NormalizeImage(image)
	if img == "" {
		return nil
	}
	for _, t := range c.Tools {
		for _, want := range t.Images {
			if img == strings.ToLower(want) {
				return t
			}
		}
	}
	return nil
}

// Template finds a GitLab security template by include path or component.
func (c *Catalog) Template(name string) *GitLabTemplate {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, t := range c.Templates {
		for _, want := range t.Templates {
			if strings.EqualFold(n, want) || strings.HasSuffix(n, "/"+strings.ToLower(want)) {
				return t
			}
		}
		for _, want := range t.Components {
			comp := n
			if i := strings.Index(comp, "@"); i >= 0 {
				comp = comp[:i]
			}
			if strings.HasSuffix(comp, strings.ToLower(want)) {
				return t
			}
		}
	}
	return nil
}

// TemplateForJob finds the template that defines a job name.
func (c *Catalog) TemplateForJob(job string) *GitLabTemplate {
	for _, t := range c.Templates {
		for _, j := range t.Jobs {
			if j == job {
				return t
			}
		}
	}
	return nil
}

// TemplateByID returns a template by ID.
func (c *Catalog) TemplateByID(id string) *GitLabTemplate {
	for _, t := range c.Templates {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// commandBase reduces a command word to the name used for matching:
// "/usr/local/bin/trivy.exe" becomes "trivy".
func commandBase(word string) string {
	b := path.Base(strings.ReplaceAll(word, `\`, "/"))
	return strings.TrimSuffix(strings.ToLower(b), ".exe")
}

// packageBase strips version specifiers from a package name:
// "snyk@1.2" and "bandit==1.7" become "snyk" and "bandit".
func packageBase(word string) string {
	w := strings.ToLower(word)
	if strings.HasPrefix(w, "@") {
		if i := strings.Index(w[1:], "@"); i >= 0 {
			w = w[:i+1]
		}
	} else if i := strings.Index(w, "@"); i >= 0 {
		w = w[:i]
	}
	if i := strings.IndexAny(w, "=<>~!["); i >= 0 {
		w = w[:i]
	}
	return w
}
