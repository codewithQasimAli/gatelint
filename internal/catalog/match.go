package catalog

import (
	"strings"
)

// Arg is one word of a command line. Known is false when the value depends
// on something gatelint cannot resolve (a variable, an expression, a command
// substitution).
type Arg struct {
	Value  string
	Known  bool
	Line   int
	Column int
}

// Lit builds known arguments from strings; it is mainly useful in tests.
func Lit(words ...string) []Arg {
	out := make([]Arg, len(words))
	for i, w := range words {
		out[i] = Arg{Value: w, Known: true}
	}
	return out
}

// Match is a scanner recognised in a command line.
type Match struct {
	Tool *Tool
	// Args are the arguments after the scanner's command words.
	Args []Arg
	// Env holds environment variables set on the command line by env(1),
	// inline assignments or docker -e.
	Env map[string]string
	// Via describes how the scanner was launched ("docker run", "npx").
	Via string
	// Start is the first word of the scanner command itself.
	Start Arg
}

var wrappers = map[string]bool{
	"sudo": true, "env": true, "timeout": true, "time": true, "nice": true, "nohup": true,
	"exec": true, "command": true, "stdbuf": true, "ionice": true, "xargs": true,
}

// wrapperValueFlags lists wrapper options that consume the next word.
var wrapperValueFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"nice":    {"-n": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"ionice":  {"-c": true, "-n": true},
	"xargs":   {"-I": true, "-n": true, "-P": true, "-d": true, "-L": true, "-s": true, "-E": true, "-a": true},
}

var pythonLaunchers = map[string]bool{"python": true, "python3": true, "py": true, "pypy3": true}

// MatchCommand recognises a scanner in a command line. It strips wrappers
// such as sudo, env and timeout, launchers such as "python -m", pipx, npx
// and poetry, and container runs such as "docker run IMAGE".
func (c *Catalog) MatchCommand(words []Arg) (*Match, bool) {
	env := map[string]string{}
	m, ok := c.match(words, env, "", 0)
	if !ok {
		return nil, false
	}
	m.Env = env
	if m.Tool.skip(m.Args) {
		return nil, false
	}
	return m, true
}

func (c *Catalog) match(words []Arg, env map[string]string, via string, depth int) (*Match, bool) {
	if depth > 8 {
		return nil, false
	}
	words = stripWrappers(words, env)
	if len(words) == 0 || !words[0].Known {
		return nil, false
	}
	first := commandBase(words[0].Value)

	// python -m module
	if isPython(first) {
		for i := 1; i < len(words); i++ {
			w := words[i].Value
			if w == "-m" && i+1 < len(words) {
				mod := strings.ToLower(words[i+1].Value)
				for _, t := range c.Tools {
					for _, pm := range t.PythonModules {
						if mod == strings.ToLower(pm) {
							return &Match{Tool: t, Args: words[i+2:], Via: joinVia(via, "python -m"), Start: words[0]}, true
						}
					}
				}
				return nil, false
			}
			if !strings.HasPrefix(w, "-") {
				return nil, false
			}
		}
		return nil, false
	}

	// Package runners.
	if rest, name, ok := stripRunner(words); ok {
		if len(rest) == 0 {
			return nil, false
		}
		// A runner may launch a package whose name differs from its command.
		pkg := packageBase(rest[0].Value)
		for _, t := range c.Tools {
			for _, p := range t.Packages {
				if pkg == strings.ToLower(p) {
					m, ok := c.matchTool(t, append([]Arg{{Value: t.firstCommandWord(pkg), Known: true, Line: rest[0].Line, Column: rest[0].Column}}, rest[1:]...))
					if ok {
						m.Via = joinVia(via, name)
						m.Start = rest[0]
						return m, true
					}
					return &Match{Tool: t, Args: rest[1:], Via: joinVia(via, name), Start: rest[0]}, true
				}
			}
		}
		return c.match(rest, env, joinVia(via, name), depth+1)
	}

	// Container runs.
	if first == "docker" || first == "podman" || first == "nerdctl" {
		return c.matchDocker(words, env, joinVia(via, first+" run"), depth)
	}

	for _, t := range c.Tools {
		if m, ok := c.matchTool(t, words); ok {
			m.Via = via
			return m, true
		}
	}
	return nil, false
}

func joinVia(a, b string) string {
	if a == "" {
		return b
	}
	return a + ", " + b
}

func isPython(word string) bool {
	if pythonLaunchers[word] {
		return true
	}
	// python3.12 and similar
	return strings.HasPrefix(word, "python3.") || strings.HasPrefix(word, "python2.")
}

// matchTool matches the tool's multi-word commands at the start of words.
func (c *Catalog) matchTool(t *Tool, words []Arg) (*Match, bool) {
	for _, cmd := range t.Commands {
		parts := strings.Fields(cmd)
		if len(parts) == 0 || len(words) < len(parts) {
			continue
		}
		ok := true
		for i, p := range parts {
			if !words[i].Known {
				ok = false
				break
			}
			w := words[i].Value
			if i == 0 {
				w = commandBase(w)
			}
			if !strings.EqualFold(w, p) {
				ok = false
				break
			}
		}
		if ok {
			return &Match{Tool: t, Args: words[len(parts):], Start: words[0]}, true
		}
	}
	return nil, false
}

func (t *Tool) firstCommandWord(fallback string) string {
	for _, c := range t.Commands {
		if f := strings.Fields(c); len(f) > 0 {
			return f[0]
		}
	}
	return fallback
}

// stripWrappers removes leading wrapper commands and records env(1)
// assignments.
func stripWrappers(words []Arg, env map[string]string) []Arg {
	for len(words) > 0 && words[0].Known {
		name := commandBase(words[0].Value)
		if !wrappers[name] {
			return words
		}
		words = words[1:]
		valueFlags := wrapperValueFlags[name]
		for len(words) > 0 {
			w := words[0].Value
			switch {
			case name == "env" && strings.Contains(w, "=") && !strings.HasPrefix(w, "-"):
				k, v, _ := strings.Cut(w, "=")
				if words[0].Known {
					env[k] = v
				}
				words = words[1:]
				continue
			case strings.HasPrefix(w, "-") && w != "-":
				words = words[1:]
				if valueFlags[w] && len(words) > 0 {
					words = words[1:]
				}
				continue
			}
			break
		}
		if name == "timeout" && len(words) > 0 {
			words = words[1:] // the duration
		}
	}
	return words
}

// stripRunner removes package runners such as "pipx run" or "npx --yes" and
// returns the remaining words.
func stripRunner(words []Arg) ([]Arg, string, bool) {
	if len(words) == 0 {
		return nil, "", false
	}
	first := commandBase(words[0].Value)
	second := ""
	if len(words) > 1 {
		second = strings.ToLower(words[1].Value)
	}
	third := ""
	if len(words) > 2 {
		third = strings.ToLower(words[2].Value)
	}
	var rest []Arg
	var name string
	valueFlags := map[string]bool{}
	switch {
	case first == "npx" || first == "pnpx" || first == "bunx" || first == "uvx":
		rest, name = words[1:], first
		valueFlags = map[string]bool{"-p": true, "--package": true, "--from": true, "--with": true, "--python": true}
	case first == "pipx" && second == "run":
		rest, name = words[2:], "pipx run"
		valueFlags = map[string]bool{"--spec": true, "--python": true, "--pip-args": true, "--index-url": true}
	case first == "uv" && second == "tool" && third == "run":
		rest, name = words[3:], "uv tool run"
		valueFlags = map[string]bool{"--from": true, "--with": true, "--python": true}
	case (first == "uv" || first == "poetry" || first == "pipenv" || first == "pdm" || first == "hatch" || first == "rye") && second == "run":
		rest, name = words[2:], first+" run"
		valueFlags = map[string]bool{"--with": true, "--python": true, "--project": true, "--directory": true, "--env": true, "-e": true}
	case (first == "pnpm" || first == "yarn") && (second == "dlx" || second == "exec"):
		rest, name = words[2:], first+" "+second
		valueFlags = map[string]bool{"-p": true, "--package": true}
	case first == "npm" && second == "exec":
		rest, name = words[2:], "npm exec"
		valueFlags = map[string]bool{"-p": true, "--package": true}
	case first == "bundle" && second == "exec":
		rest, name = words[2:], "bundle exec"
	case first == "go" && second == "run":
		rest, name = words[2:], "go run"
	default:
		return nil, "", false
	}
	for len(rest) > 0 && strings.HasPrefix(rest[0].Value, "-") {
		f := rest[0].Value
		rest = rest[1:]
		if f == "--" {
			break
		}
		if valueFlags[f] && len(rest) > 0 {
			rest = rest[1:]
		}
	}
	return rest, name, true
}

// dockerValueFlags lists "docker run" options that consume the next word.
var dockerValueFlags = map[string]bool{
	"-a": true, "--attach": true, "-c": true, "--cpu-shares": true, "--cidfile": true, "--cpus": true,
	"--device": true, "--dns": true, "-e": true, "--env": true, "--env-file": true, "--entrypoint": true,
	"--group-add": true, "-h": true, "--hostname": true, "--ip": true, "-l": true, "--label": true,
	"--log-driver": true, "--log-opt": true, "-m": true, "--memory": true, "--mount": true, "--name": true,
	"--network": true, "--net": true, "-p": true, "--publish": true, "--platform": true, "--pull": true,
	"--restart": true, "--runtime": true, "--security-opt": true, "--shm-size": true, "--tmpfs": true,
	"-u": true, "--user": true, "--ulimit": true, "-v": true, "--volume": true, "--volumes-from": true,
	"-w": true, "--workdir": true, "--add-host": true, "--cap-add": true, "--cap-drop": true, "--userns": true,
	"--gpus": true, "--pid": true, "--ipc": true, "--stop-signal": true, "--stop-timeout": true, "--health-cmd": true,
}

func (c *Catalog) matchDocker(words []Arg, env map[string]string, via string, depth int) (*Match, bool) {
	i := 1
	if i < len(words) && words[i].Value == "container" {
		i++
	}
	if i >= len(words) || words[i].Value != "run" {
		return nil, false
	}
	i++
	entrypoint := ""
	for i < len(words) {
		w := words[i].Value
		if !strings.HasPrefix(w, "-") {
			break
		}
		name, val, hasEq := strings.Cut(w, "=")
		if dockerValueFlags[name] && !hasEq {
			if i+1 < len(words) {
				val = words[i+1].Value
				if (name == "-e" || name == "--env") && words[i+1].Known {
					if k, v, ok := strings.Cut(val, "="); ok {
						env[k] = v
					}
				}
			}
			i += 2
		} else {
			if (name == "-e" || name == "--env") && hasEq {
				if k, v, ok := strings.Cut(val, "="); ok {
					env[k] = v
				}
			}
			i++
		}
		if name == "--entrypoint" {
			entrypoint = val
		}
	}
	if i >= len(words) || !words[i].Known {
		return nil, false
	}
	image := words[i]
	rest := words[i+1:]
	t := c.Image(image.Value)
	if t == nil {
		return nil, false
	}
	if entrypoint != "" {
		rest = append([]Arg{{Value: entrypoint, Known: true, Line: image.Line, Column: image.Column}}, rest...)
	}
	// "docker run semgrep/semgrep semgrep ci": drop the explicit command.
	if len(rest) > 0 {
		if m, ok := c.matchTool(t, rest); ok {
			m.Via = via
			m.Start = image
			return m, true
		}
		if sub, ok := c.match(rest, env, via, depth+1); ok && sub.Tool == t {
			sub.Start = image
			return sub, true
		}
	}
	return &Match{Tool: t, Args: rest, Via: via, Start: image}, true
}

// skip reports whether the invocation only prints help or version
// information, or does not scan.
func (t *Tool) skip(args []Arg) bool {
	for _, a := range args {
		for _, f := range t.SkipFlags {
			if a.Value == f {
				return true
			}
		}
	}
	pos := positionals(args, t.valueFlags())
	if len(pos) > 0 {
		for _, s := range t.SkipSubcommands {
			if pos[0] == s {
				return true
			}
		}
	}
	return false
}

// valueFlags returns flag names that take a value, so positional arguments
// can be told apart from flag values.
func (t *Tool) valueFlags() map[string]bool {
	out := map[string]bool{}
	add := func(ss []Setting) {
		for _, s := range ss {
			if s.TakesValue {
				for _, n := range s.Names {
					out[n] = true
				}
			}
		}
	}
	add(t.Settings)
	for _, m := range t.Modes {
		add(m.Settings)
	}
	for _, f := range t.ConfigFlags {
		out[f] = true
	}
	for _, f := range t.OutputFlags {
		out[f] = true
	}
	return out
}

func positionals(args []Arg, valueFlags map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		v := args[i].Value
		if strings.HasPrefix(v, "-") && v != "-" {
			if valueFlags[v] {
				i++
			}
			continue
		}
		out = append(out, v)
	}
	return out
}
