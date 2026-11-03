package catalog

import (
	"strconv"
	"strings"
)

// Hit is a setting that matched in a command line, environment or action
// inputs.
type Hit struct {
	// Name is the flag, environment variable or input name as written.
	Name  string
	Value string
	// Arg is the argument holding the flag (zero for env and inputs).
	Arg Arg
	// FromEnv is true when the setting came from an environment variable.
	FromEnv bool
	Desc    string
}

// Label renders the hit as it appeared, e.g. "--exit-code 0".
func (h Hit) Label() string {
	switch {
	case h.FromEnv:
		return h.Name + "=" + h.Value
	case h.Value == "" || h.Value == "true" && !strings.Contains(h.Arg.Value, "="):
		return h.Name
	case strings.Contains(h.Arg.Value, "="):
		return h.Arg.Value
	default:
		return h.Name + " " + h.Value
	}
}

// Eval is the gating evaluation of one scanner invocation.
type Eval struct {
	Mode *Mode
	// GatesByDefault reports the tool or action default.
	GatesByDefault bool
	// NeverGates is set for modes such as "snyk monitor" that cannot fail
	// on findings, and InfoOnly for tools whose results gate elsewhere
	// (code scanning).
	NeverGates bool
	InfoOnly   bool
	Neuters    []Hit
	Gates      []Hit
	// Unknown lists relevant settings whose value cannot be resolved.
	Unknown []Hit
	// ConfigFile is set when a configuration file may change gating.
	ConfigFile string
	// FailCodes are the exit codes the scanner uses when it fails a build.
	FailCodes []int
	// Outputs are report files the invocation writes.
	Outputs []string
	Note    string
}

// Gating reports whether the invocation fails the build on findings, as far
// as flags and inputs show.
func (e *Eval) Gating() bool {
	if len(e.Neuters) > 0 || e.NeverGates || e.InfoOnly {
		return false
	}
	return e.GatesByDefault || len(e.Gates) > 0
}

// Indeterminate reports whether gating depends on values gatelint cannot see.
func (e *Eval) Indeterminate() bool {
	return !e.Gating() && len(e.Neuters) == 0 && !e.NeverGates && !e.InfoOnly && (len(e.Unknown) > 0 || e.ConfigFile != "")
}

// selectMode picks the mode matching the first positional arguments.
func (t *Tool) selectMode(args []Arg, command string) *Mode {
	pos := positionals(args, t.valueFlags())
	if command != "" {
		pos = append(strings.Fields(command), pos...)
	}
	if len(pos) > 2 {
		pos = pos[:2]
	}
	var fallback *Mode
	for i := range t.Modes {
		m := &t.Modes[i]
		if len(m.Subcommands) == 0 {
			if fallback == nil {
				fallback = m
			}
			continue
		}
		for _, p := range pos {
			for _, s := range m.Subcommands {
				if p == s {
					return m
				}
			}
		}
	}
	if fallback == nil {
		fallback = &Mode{GatesByDefault: true}
	}
	return fallback
}

// settings returns the tool settings plus those of the mode.
func (t *Tool) settings(m *Mode) []Setting {
	out := append([]Setting{}, t.Settings...)
	if m != nil {
		out = append(out, m.Settings...)
	}
	return out
}

// Evaluate classifies a command-line invocation. env holds known
// environment variables in effect; repoFiles reports whether a file exists
// at the repository root (it may be nil).
func (t *Tool) Evaluate(args []Arg, env map[string]string, repoFiles func(string) bool) *Eval {
	return t.evaluate(args, env, repoFiles, "")
}

func (t *Tool) evaluate(args []Arg, env map[string]string, repoFiles func(string) bool, command string) *Eval {
	m := t.selectMode(args, command)
	e := &Eval{Mode: m, GatesByDefault: m.GatesByDefault, NeverGates: m.NeverGates, InfoOnly: t.InfoOnly, Note: m.Note}
	if e.Note == "" {
		e.Note = t.Note
	}
	failCode := -1
	settings := t.settings(m)
	// Environment first, so explicit flags override it.
	for _, s := range settings {
		if s.Env == "" {
			continue
		}
		if v, ok := env[s.Env]; ok {
			h := Hit{Name: s.Env, Value: v, FromEnv: true, Desc: s.Desc}
			known := !strings.Contains(v, "$")
			classify(e, s, h, known, &failCode)
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasEq := strings.Cut(a.Value, "=")
		for _, s := range settings {
			if !contains(s.Names, name) {
				continue
			}
			known := a.Known
			switch {
			case s.TakesValue && hasEq:
			case s.TakesValue:
				if i+1 < len(args) {
					val = args[i+1].Value
					known = args[i+1].Known
					i++
				} else {
					val = ""
				}
			case hasEq:
				// --soft-fail=false
			default:
				val = "true"
			}
			classify(e, s, Hit{Name: name, Value: val, Arg: a, Desc: s.Desc}, known, &failCode)
		}
		if contains(t.ConfigFlags, name) && e.ConfigFile == "" {
			e.ConfigFile = val
			if !hasEq && i+1 < len(args) {
				e.ConfigFile = args[i+1].Value
			}
			if e.ConfigFile == "" {
				e.ConfigFile = name
			}
		}
		if contains(t.OutputFlags, name) {
			out := val
			if !hasEq && i+1 < len(args) {
				out = args[i+1].Value
			}
			if out != "" {
				e.Outputs = append(e.Outputs, out)
			}
		}
	}
	if e.ConfigFile == "" && repoFiles != nil {
		for _, f := range t.DefaultConfigFiles {
			if repoFiles(f) {
				e.ConfigFile = f
				break
			}
		}
	}
	e.FailCodes = t.FailExitCodes
	if failCode > 0 {
		e.FailCodes = []int{failCode}
	}
	return e
}

func classify(e *Eval, s Setting, h Hit, known bool, failCode *int) {
	if !known {
		e.Unknown = append(e.Unknown, h)
		return
	}
	// A later occurrence of the same flag overrides an earlier one.
	e.Neuters = dropSetting(e.Neuters, s)
	e.Gates = dropSetting(e.Gates, s)
	e.Unknown = dropSetting(e.Unknown, s)
	if s.ExitCode {
		if n, err := strconv.Atoi(strings.TrimSpace(h.Value)); err == nil {
			*failCode = n
		}
	}
	switch {
	case matches(s.NeuterWhen, h.Value) || containsFold(s.NeuterValues, h.Value):
		e.Neuters = append(e.Neuters, h)
	case matches(s.GateWhen, h.Value):
		e.Gates = append(e.Gates, h)
	}
}

func dropSetting(hits []Hit, s Setting) []Hit {
	out := hits[:0]
	for _, h := range hits {
		if contains(s.Names, h.Name) || (s.Env != "" && h.Name == s.Env) {
			continue
		}
		out = append(out, h)
	}
	return out
}

func matches(c Condition, v string) bool {
	v = strings.TrimSpace(strings.Trim(v, `"'`))
	switch c {
	case CondSet:
		return v == "" || isTrue(v)
	case CondZero:
		n, err := strconv.Atoi(v)
		return err == nil && n == 0
	case CondNonZero:
		n, err := strconv.Atoi(v)
		return err == nil && n != 0
	case CondAny:
		return v != ""
	case CondTrue:
		return isTrue(v)
	case CondFalse:
		return isFalse(v)
	}
	return false
}

func isTrue(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func isFalse(v string) bool {
	switch strings.ToLower(v) {
	case "false", "0", "no", "off":
		return true
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	s = strings.Trim(s, `"'`)
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// InputValue is a GitHub Action input as seen by the evaluator.
type InputValue struct {
	Value string
	Known bool
}

// EvaluateAction classifies a GitHub Action step. inputs maps input names to
// values; args are the tokenised args input, if the action has one; env is
// the step environment.
func (t *Tool) EvaluateAction(a *Action, inputs map[string]InputValue, args []Arg, env map[string]string, repoFiles func(string) bool) *Eval {
	command := a.DefaultCommand
	if a.CommandInput != "" {
		if v, ok := lookupInput(inputs, a.CommandInput); ok && v.Known && strings.TrimSpace(v.Value) != "" {
			command = v.Value
		}
	}
	var e *Eval
	if a.ArgsInput != "" || a.CommandInput != "" || a.HonourEnv {
		if !a.HonourEnv {
			env = nil
		}
		e = t.evaluate(args, env, nil, command)
		if a.CommandInput == "" {
			e.NeverGates = false
		}
	} else {
		e = &Eval{FailCodes: t.FailExitCodes}
	}
	if !e.NeverGates {
		e.GatesByDefault = a.GatesByDefault
	}
	e.InfoOnly = a.InfoOnly
	if a.Note != "" {
		e.Note = a.Note
	}
	failCode := -1
	for _, s := range a.Inputs {
		for _, n := range s.Names {
			v, ok := lookupInput(inputs, n)
			if !ok {
				continue
			}
			classify(e, s, Hit{Name: n, Value: v.Value, Desc: s.Desc}, v.Known, &failCode)
		}
	}
	if failCode > 0 {
		e.FailCodes = []int{failCode}
	}
	for _, n := range a.ConfigInputs {
		if v, ok := lookupInput(inputs, n); ok && strings.TrimSpace(v.Value) != "" && e.ConfigFile == "" {
			e.ConfigFile = v.Value
		}
	}
	for _, n := range a.OutputInputs {
		if v, ok := lookupInput(inputs, n); ok && v.Value != "" {
			e.Outputs = append(e.Outputs, v.Value)
		}
	}
	return e
}

func lookupInput(inputs map[string]InputValue, name string) (InputValue, bool) {
	if v, ok := inputs[name]; ok {
		return v, true
	}
	for k, v := range inputs {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return InputValue{}, false
}
