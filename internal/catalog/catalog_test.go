package catalog

import (
	"strings"
	"testing"
)

func TestDefaultCatalogIsValid(t *testing.T) {
	c := Default()
	for _, id := range []string{"bandit", "trivy", "grype", "semgrep", "gitleaks", "checkov", "tfsec", "npm-audit", "pip-audit", "snyk", "codeql"} {
		if c.Tool(id) == nil {
			t.Errorf("missing scanner %s", id)
		}
	}
	if c.Tool("nope") != nil {
		t.Error("unknown tool found")
	}
	if names := c.Names(); len(names) != len(c.Tools) || names[0] > names[1] {
		t.Errorf("names = %v", names)
	}
}

func match(t *testing.T, words ...string) *Match {
	t.Helper()
	m, ok := Default().MatchCommand(Lit(words...))
	if !ok {
		t.Fatalf("%v did not match", words)
	}
	return m
}

func TestMatchCommand(t *testing.T) {
	cases := []struct {
		words []string
		tool  string
		args  int
		via   string
	}{
		{[]string{"trivy", "fs", "."}, "trivy", 2, ""},
		{[]string{"/usr/local/bin/trivy.exe", "fs"}, "trivy", 1, ""},
		{[]string{"python", "-m", "bandit", "-r", "."}, "bandit", 2, "python -m"},
		{[]string{"python3.12", "-u", "-m", "pip_audit"}, "pip-audit", 0, "python -m"},
		{[]string{"pipx", "run", "--spec", "bandit==1.7", "bandit", "-r", "."}, "bandit", 2, "pipx run"},
		{[]string{"uvx", "pip-audit"}, "pip-audit", 0, "uvx"},
		{[]string{"uv", "tool", "run", "bandit"}, "bandit", 0, "uv tool run"},
		{[]string{"poetry", "run", "bandit", "-r", "."}, "bandit", 2, "poetry run"},
		{[]string{"npx", "--yes", "snyk@1.1290.0", "test"}, "snyk", 1, "npx"},
		{[]string{"npx", "-p", "x", "@snyk/protect"}, "", 0, ""},
		{[]string{"pnpm", "dlx", "snyk", "test"}, "snyk", 1, "pnpm dlx"},
		{[]string{"npm", "audit", "--audit-level=high"}, "npm-audit", 1, ""},
		{[]string{"yarn", "npm", "audit"}, "npm-audit", 0, ""},
		{[]string{"sudo", "-u", "root", "env", "A=1", "timeout", "-k", "5", "10m", "gitleaks", "detect"}, "gitleaks", 1, ""},
		{[]string{"docker", "run", "--rm", "-v", "x:/src", "-e", "TRIVY_EXIT_CODE=0", "aquasec/trivy:0.58.1", "fs", "/src"}, "trivy", 2, "docker run"},
		{[]string{"docker", "container", "run", "--env=A=1", "docker.io/semgrep/semgrep:latest", "semgrep", "ci"}, "semgrep", 1, "docker run"},
		{[]string{"podman", "run", "--entrypoint", "trivy", "ghcr.io/aquasecurity/trivy@sha256:abc", "fs"}, "trivy", 1, "podman run"},
		{[]string{"codeql", "database", "analyze", "db"}, "codeql", 1, ""},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.words, " "), func(t *testing.T) {
			m, ok := Default().MatchCommand(Lit(c.words...))
			if c.tool == "" {
				if ok {
					t.Fatalf("matched %s", m.Tool.ID)
				}
				return
			}
			if !ok {
				t.Fatal("no match")
			}
			if m.Tool.ID != c.tool || len(m.Args) != c.args || m.Via != c.via {
				t.Errorf("got tool=%s args=%d via=%q", m.Tool.ID, len(m.Args), m.Via)
			}
		})
	}
	if m := match(t, "docker", "run", "-e", "TRIVY_EXIT_CODE=0", "aquasec/trivy", "fs"); m.Env["TRIVY_EXIT_CODE"] != "0" {
		t.Errorf("docker env = %v", m.Env)
	}
	if m := match(t, "env", "GRYPE_FAIL_ON_SEVERITY=high", "grype", "dir:."); m.Env["GRYPE_FAIL_ON_SEVERITY"] != "high" {
		t.Errorf("env(1) env = %v", m.Env)
	}
}

func TestMatchRejects(t *testing.T) {
	for _, words := range [][]string{
		{"echo", "trivy"},
		{"trivy", "--version"},
		{"trivy", "version"},
		{"python", "-m", "pip", "install", "bandit"},
		{"python", "script.py"},
		{"docker", "pull", "aquasec/trivy"},
		{"docker", "run", "alpine", "trivy"},
		{"docker", "run"},
		{"npm", "audit", "fix"},
		{"pipx", "run"},
		{"snyk", "auth", "TOKEN"},
		{"python"},
		{},
	} {
		if m, ok := Default().MatchCommand(Lit(words...)); ok {
			t.Errorf("%v matched %s", words, m.Tool.ID)
		}
	}
	if _, ok := Default().MatchCommand([]Arg{{Value: "$SCANNER"}}); ok {
		t.Error("unknown command word matched")
	}
}

func eval(t *testing.T, env map[string]string, words ...string) *Eval {
	t.Helper()
	m := match(t, words...)
	return m.Tool.Evaluate(m.Args, env, nil)
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		words   []string
		env     map[string]string
		gating  bool
		neuters int
		unknown bool
	}{
		{[]string{"trivy", "fs", "."}, nil, false, 0, false},
		{[]string{"trivy", "fs", "--exit-code", "1", "."}, nil, true, 0, false},
		{[]string{"trivy", "fs", "--exit-code=0", "."}, nil, false, 1, false},
		{[]string{"trivy", "fs", "."}, map[string]string{"TRIVY_EXIT_CODE": "2"}, true, 0, false},
		{[]string{"trivy", "fs", "--exit-code", "1"}, map[string]string{"TRIVY_EXIT_CODE": "0"}, true, 0, false},
		{[]string{"trivy", "fs", "."}, map[string]string{"TRIVY_EXIT_CODE": "$CODE"}, false, 0, true},
		{[]string{"trivy", "fs", "--config", "t.yaml"}, nil, false, 0, true},
		{[]string{"grype", "dir:.", "-f", "high"}, nil, true, 0, false},
		{[]string{"semgrep", "ci"}, nil, true, 0, false},
		{[]string{"semgrep", "scan", "--error"}, nil, true, 0, false},
		{[]string{"semgrep", "--config", "auto"}, nil, false, 0, false},
		{[]string{"bandit", "-r", ".", "--exit-zero"}, nil, false, 1, false},
		{[]string{"checkov", "-d", ".", "--soft-fail=false"}, nil, true, 0, false},
		{[]string{"checkov", "-d", ".", "--soft-fail=true"}, nil, false, 1, false},
		{[]string{"npm", "audit", "--audit-level", "none"}, nil, false, 1, false},
		{[]string{"npm", "audit"}, map[string]string{"npm_config_audit_level": "none"}, false, 1, false},
		{[]string{"gitleaks", "detect", "--exit-code", "0", "--exit-code", "1"}, nil, true, 0, false},
		{[]string{"snyk", "monitor"}, nil, false, 0, false},
		{[]string{"snyk", "--org", "acme", "monitor"}, nil, false, 0, false},
		{[]string{"snyk", "test"}, nil, true, 0, false},
		{[]string{"trufflehog", "git", "--fail"}, nil, true, 0, false},
		{[]string{"gosec", "-no-fail", "./..."}, nil, false, 1, false},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.words, " "), func(t *testing.T) {
			e := eval(t, c.env, c.words...)
			if e.Gating() != c.gating || len(e.Neuters) != c.neuters || e.Indeterminate() != c.unknown {
				t.Errorf("gating=%v neuters=%d indeterminate=%v (%+v)", e.Gating(), len(e.Neuters), e.Indeterminate(), e)
			}
		})
	}
	if e := eval(t, nil, "snyk", "monitor"); !e.NeverGates || e.Note == "" {
		t.Errorf("snyk monitor = %+v", e)
	}
	if e := eval(t, nil, "codeql", "database", "analyze"); !e.InfoOnly {
		t.Errorf("codeql = %+v", e)
	}
	unknown := match(t, "trivy", "fs", "--exit-code")
	unknown.Args[1].Known = true
	if e := unknown.Tool.Evaluate([]Arg{{Value: "--exit-code", Known: true}, {Value: "$X"}}, nil, nil); !e.Indeterminate() {
		t.Errorf("unknown flag value = %+v", e)
	}
}

func TestEvaluateExitCodesAndOutputs(t *testing.T) {
	e := eval(t, nil, "trivy", "fs", "--exit-code", "5", "-o", "out.json", "--output=two.json")
	if len(e.FailCodes) != 1 || e.FailCodes[0] != 5 {
		t.Errorf("fail codes = %v", e.FailCodes)
	}
	if len(e.Outputs) != 2 || e.Outputs[0] != "out.json" || e.Outputs[1] != "two.json" {
		t.Errorf("outputs = %v", e.Outputs)
	}
	if e := eval(t, nil, "grype", "dir:.", "--fail-on", "high"); e.FailCodes[0] != 2 {
		t.Errorf("grype fail codes = %v", e.FailCodes)
	}
	if e := eval(t, nil, "bandit", "-r", "."); e.FailCodes[0] != 1 {
		t.Errorf("default fail codes = %v", e.FailCodes)
	}
	m := match(t, "grype", "dir:.")
	if e := m.Tool.Evaluate(m.Args, nil, func(name string) bool { return name == ".grype.yaml" }); e.ConfigFile != ".grype.yaml" || !e.Indeterminate() {
		t.Errorf("default config = %+v", e)
	}
}

func TestHitLabel(t *testing.T) {
	cases := []struct {
		h    Hit
		want string
	}{
		{Hit{Name: "--exit-zero", Value: "true", Arg: Arg{Value: "--exit-zero"}}, "--exit-zero"},
		{Hit{Name: "--exit-code", Value: "0", Arg: Arg{Value: "--exit-code"}}, "--exit-code 0"},
		{Hit{Name: "--audit-level", Value: "none", Arg: Arg{Value: "--audit-level=none"}}, "--audit-level=none"},
		{Hit{Name: "TRIVY_EXIT_CODE", Value: "0", FromEnv: true}, "TRIVY_EXIT_CODE=0"},
	}
	for _, c := range cases {
		if got := c.h.Label(); got != c.want {
			t.Errorf("Label() = %q, want %q", got, c.want)
		}
	}
}

func TestActions(t *testing.T) {
	c := Default()
	cases := []struct {
		uses string
		tool string
	}{
		{"aquasecurity/trivy-action@0.28.0", "trivy"},
		{"AquaSecurity/Trivy-Action@master", "trivy"},
		{"snyk/actions/node@master", "snyk"},
		{"snyk/actions@master", "snyk"},
		{"github/codeql-action/analyze@v3", "codeql"},
		{"github/codeql-action/init@v3", ""},
		{"actions/checkout@v4", ""},
	}
	for _, x := range cases {
		tool, a := c.Action(x.uses)
		switch {
		case x.tool == "" && tool != nil:
			t.Errorf("%s matched %s", x.uses, tool.ID)
		case x.tool != "" && (tool == nil || tool.ID != x.tool || a == nil):
			t.Errorf("%s did not match %s", x.uses, x.tool)
		}
	}
}

func TestEvaluateAction(t *testing.T) {
	c := Default()
	trivy, ta := c.Action("aquasecurity/trivy-action@v1")
	e := trivy.EvaluateAction(ta, map[string]InputValue{}, nil, nil, nil)
	if e.Gating() || len(e.Neuters) != 0 {
		t.Errorf("trivy-action default = %+v", e)
	}
	e = trivy.EvaluateAction(ta, map[string]InputValue{"exit-code": {Value: "0", Known: true}, "output": {Value: "r.sarif", Known: true}}, nil, nil, nil)
	if len(e.Neuters) != 1 || e.Outputs[0] != "r.sarif" {
		t.Errorf("trivy-action exit-code 0 = %+v", e)
	}
	e = trivy.EvaluateAction(ta, map[string]InputValue{"Exit-Code": {Value: "1", Known: true}}, nil, nil, nil)
	if !e.Gating() || e.FailCodes[0] != 1 {
		t.Errorf("trivy-action exit-code 1 = %+v", e)
	}
	e = trivy.EvaluateAction(ta, map[string]InputValue{}, nil, map[string]string{"TRIVY_EXIT_CODE": "1"}, nil)
	if !e.Gating() {
		t.Errorf("trivy-action env = %+v", e)
	}
	e = trivy.EvaluateAction(ta, map[string]InputValue{"trivy-config": {Value: "trivy.yaml", Known: true}}, nil, nil, nil)
	if !e.Indeterminate() {
		t.Errorf("trivy-action config = %+v", e)
	}
	e = trivy.EvaluateAction(ta, map[string]InputValue{"exit-code": {Value: "${{ inputs.c }}"}}, nil, nil, nil)
	if !e.Indeterminate() {
		t.Errorf("trivy-action expression = %+v", e)
	}

	snyk, sa := c.Action("snyk/actions/docker@master")
	if e := snyk.EvaluateAction(sa, map[string]InputValue{"command": {Value: "monitor", Known: true}}, nil, nil, nil); !e.NeverGates {
		t.Errorf("snyk monitor action = %+v", e)
	}
	if e := snyk.EvaluateAction(sa, map[string]InputValue{}, Lit("--all-projects"), nil, nil); !e.Gating() {
		t.Errorf("snyk test action = %+v", e)
	}
	gosec, ga := c.Action("securego/gosec@v2")
	if e := gosec.EvaluateAction(ga, nil, Lit("-no-fail", "./..."), nil, nil); len(e.Neuters) != 1 {
		t.Errorf("gosec args = %+v", e)
	}
	codeql, ca := c.Action("github/codeql-action/analyze@v3")
	if e := codeql.EvaluateAction(ca, nil, nil, nil, nil); !e.InfoOnly || e.Gating() {
		t.Errorf("codeql action = %+v", e)
	}
	if got := trivy.GateExample(trivy.selectMode(nil, ""), ta); got != "exit-code: '1'" {
		t.Errorf("trivy action example = %q", got)
	}
	if got := trivy.GateExample(trivy.selectMode(nil, ""), nil); got != "--exit-code 1" {
		t.Errorf("trivy CLI example = %q", got)
	}
	if got := codeql.GateExample(nil, ca); got != "" {
		t.Errorf("codeql example = %q", got)
	}
}

func TestImagesAndTemplates(t *testing.T) {
	c := Default()
	for img, want := range map[string]string{
		"aquasec/trivy:0.58.1":                         "trivy",
		"docker.io/aquasec/trivy":                      "trivy",
		"docker://ghcr.io/aquasecurity/trivy@sha256:1": "trivy",
		"registry-1.docker.io/library/alpine:3":        "",
		"":                                             "",
		"localhost:5000/aquasec/trivy:1":               "",
	} {
		tool := c.Image(img)
		if (want == "") != (tool == nil) || (tool != nil && tool.ID != want) {
			t.Errorf("Image(%q) = %v, want %q", img, tool, want)
		}
	}
	if NormalizeImage("localhost:5000/x:1") != "localhost:5000/x" {
		t.Errorf("normalize keeps registry port: %q", NormalizeImage("localhost:5000/x:1"))
	}
	for name, want := range map[string]string{
		"Jobs/SAST.gitlab-ci.yml":                                          "gitlab-sast",
		"Security/SAST.gitlab-ci.yml":                                      "gitlab-sast",
		"$CI_SERVER_FQDN/components/secret-detection/secret-detection@1.0": "gitlab-secret-detection",
		"Jobs/Build.gitlab-ci.yml":                                         "",
	} {
		tpl := c.Template(name)
		if (want == "") != (tpl == nil) || (tpl != nil && tpl.ID != want) {
			t.Errorf("Template(%q) = %v, want %q", name, tpl, want)
		}
	}
	if tpl := c.TemplateForJob("secret_detection"); tpl == nil || tpl.ID != "gitlab-secret-detection" {
		t.Errorf("TemplateForJob = %v", tpl)
	}
	if c.TemplateForJob("build") != nil || c.TemplateByID("nope") != nil {
		t.Error("unexpected template match")
	}
	if c.TemplateByID("gitlab-dast") == nil {
		t.Error("gitlab-dast missing")
	}
}

func TestParseValidateMerge(t *testing.T) {
	extra, err := Parse([]byte(`
scanners:
  - id: mytool
    commands: [mytool]
    modes:
      - gates-by-default: true
    settings:
      - names: [--no-fail]
        neuter-when: set
  - id: trivy
    name: Trivy (custom)
    commands: [trivy]
gitlab-templates:
  - id: gitlab-sast
    name: Custom SAST
  - id: custom-template
    templates: [Custom.gitlab-ci.yml]
`))
	if err != nil {
		t.Fatal(err)
	}
	if extra.Tool("mytool").Name != "mytool" || extra.Tool("mytool").FailExitCodes[0] != 1 {
		t.Errorf("defaults not applied: %+v", extra.Tool("mytool"))
	}
	merged := Default().Merge(extra)
	if merged.Tool("trivy").Name != "Trivy (custom)" || merged.Tool("mytool") == nil || merged.Tool("bandit") == nil {
		t.Error("merge failed")
	}
	if merged.TemplateByID("gitlab-sast").Name != "Custom SAST" || merged.TemplateByID("custom-template") == nil {
		t.Error("template merge failed")
	}
	m, ok := merged.MatchCommand(Lit("mytool", "--no-fail"))
	if !ok || len(m.Tool.Evaluate(m.Args, nil, nil).Neuters) != 1 {
		t.Error("custom tool not evaluated")
	}
	if Default().Merge(nil).Tool("trivy") == nil {
		t.Error("merge with nil lost tools")
	}

	for _, bad := range []string{
		"scanners: [{name: x, commands: [x]}]",
		"scanners: [{id: x}]",
		"scanners: [{id: x, commands: [x]}, {id: x, commands: [y]}]",
		"scanners: [{id: x, commands: [x], settings: [{gate-when: set}]}]",
		"scanners: [{id: x, commands: [x], settings: [{names: [-a], gate-when: sometimes}]}]",
		"scanners: [{id: x, actions: [{gates-by-default: true}]}]",
		"gitlab-templates: [{name: x}]",
		"scanners: {",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestConditions(t *testing.T) {
	cases := []struct {
		c    Condition
		v    string
		want bool
	}{
		{CondSet, "", true}, {CondSet, "true", true}, {CondSet, "false", false},
		{CondZero, "0", true}, {CondZero, "'0'", true}, {CondZero, "1", false}, {CondZero, "x", false},
		{CondNonZero, "2", true}, {CondNonZero, "0", false},
		{CondAny, "high", true}, {CondAny, "", false},
		{CondTrue, "TRUE", true}, {CondTrue, "yes", true}, {CondTrue, "no", false},
		{CondFalse, "False", true}, {CondFalse, "off", true}, {CondFalse, "true", false},
		{Condition(""), "x", false},
	}
	for _, c := range cases {
		if got := matches(c.c, c.v); got != c.want {
			t.Errorf("matches(%s, %q) = %v", c.c, c.v, got)
		}
	}
}

func TestPackageBase(t *testing.T) {
	for in, want := range map[string]string{"snyk@1.2": "snyk", "@snyk/cli@1": "@snyk/cli", "bandit==1.7": "bandit", "Pip-Audit[toml]": "pip-audit"} {
		if got := packageBase(in); got != want {
			t.Errorf("packageBase(%q) = %q, want %q", in, got, want)
		}
	}
}
