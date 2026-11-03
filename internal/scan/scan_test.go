package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

func write(t *testing.T, root, rel, body string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const swallowWF = "on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: trivy fs --exit-code 1 . || true\n"

func ruleIDs(res *model.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func TestDiscovery(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/a.yml", swallowWF)
	write(t, root, ".github/workflows/b.yaml", swallowWF)
	write(t, root, ".github/workflows/nested/ignored.yml", swallowWF)
	write(t, root, ".github/workflows/README.md", "x")
	write(t, root, ".github/actions/x/action.yml", "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: bandit -r . --exit-zero\n")
	write(t, root, "action.yml", "runs:\n  using: node20\n  main: x.js\n")
	write(t, root, ".gitlab-ci.yml", "include: ci/x.yml\nscan:\n  script: [semgrep ci || true]\n")
	write(t, root, "ci/x.yml", "inc:\n  script: [gitleaks detect --exit-code 0]\n")
	write(t, root, "sub/.gitlab-ci.yml", "a:\n  script: [semgrep ci]\n")
	write(t, root, "testdata/.gitlab-ci.yml", "a:\n  script: [semgrep ci || true]\n")
	write(t, root, "node_modules/pkg/.github/workflows/x.yml", swallowWF)
	res, _, err := Run([]string{root}, Options{Cwd: root, NoAutoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".github/actions/x/action.yml", ".github/workflows/a.yml", ".github/workflows/b.yaml", ".gitlab-ci.yml", "action.yml", "ci/x.yml", "sub/.gitlab-ci.yml"}
	if strings.Join(res.Files, ",") != strings.Join(want, ",") {
		t.Errorf("files = %v\nwant    %v", res.Files, want)
	}
	if len(res.Findings) != 5 {
		t.Errorf("findings = %v", ruleIDs(res))
	}
	if len(res.Errors) != 0 {
		t.Errorf("errors = %v", res.Errors)
	}

	res, _, err = Run([]string{root}, Options{Cwd: root, NoAutoConfig: true, Platform: "gitlab"})
	if err != nil || len(res.Files) != 3 {
		t.Errorf("gitlab only: %v %v", err, res.Files)
	}
	res, _, err = Run([]string{root}, Options{Cwd: root, NoAutoConfig: true, Platform: "github"})
	if err != nil || len(res.Files) != 4 {
		t.Errorf("github only: %v %v", err, res.Files)
	}
}

func TestExplicitFilesAndDetection(t *testing.T) {
	root := t.TempDir()
	gh := write(t, root, "pipelines/security.yml", swallowWF)
	gl := write(t, root, "pipelines/gitlab.yml", "stages: [a]\nscan:\n  script: [semgrep ci || true]\n")
	act := write(t, root, "pipelines/meta.yml", "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: semgrep ci || true\n")
	odd := write(t, root, "pipelines/odd.yml", "foo: bar\n")
	for _, f := range []string{gh, gl, act} {
		res, _, err := Run([]string{f}, Options{Cwd: root, NoAutoConfig: true})
		if err != nil || len(res.Findings) != 1 {
			t.Errorf("%s: %v %v", f, err, ruleIDs(res))
		}
	}
	if _, _, err := Run([]string{odd}, Options{Cwd: root, NoAutoConfig: true}); err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Errorf("undetectable file: %v", err)
	}
	if res, _, err := Run([]string{odd}, Options{Cwd: root, NoAutoConfig: true, Platform: "gitlab"}); err != nil || len(res.Files) != 1 {
		t.Errorf("forced gitlab: %v %+v", err, res)
	}
	if res, _, err := Run([]string{odd}, Options{Cwd: root, NoAutoConfig: true, Platform: "github"}); err != nil || len(res.Files) != 1 {
		t.Errorf("forced github: %v %+v", err, res)
	}
	if _, _, err := Run([]string{filepath.Join(root, "missing")}, Options{Cwd: root}); err == nil {
		t.Error("missing path accepted")
	}
	if _, _, err := Run([]string{root}, Options{Cwd: root, Platform: "jenkins"}); err == nil {
		t.Error("bad platform accepted")
	}
}

func TestDisplayOutsideCwd(t *testing.T) {
	root := t.TempDir()
	f := write(t, root, ".gitlab-ci.yml", "a:\n  script: [semgrep ci || true]\n")
	res, _, err := Run([]string{f}, Options{Cwd: t.TempDir(), NoAutoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(filepath.FromSlash(res.Files[0])) {
		t.Errorf("display path = %s", res.Files[0])
	}
}

func TestLocalReferences(t *testing.T) {
	root := t.TempDir()
	caller := write(t, root, ".github/workflows/caller.yml", `on: push
jobs:
  call:
    uses: ./.github/workflows/called.yml
  missing:
    uses: ./.github/workflows/nope.yml
  steps:
    runs-on: ubuntu-latest
    steps:
      - uses: ./tools/scan-action
      - uses: ./tools/empty
`)
	write(t, root, ".github/workflows/called.yml", swallowWF)
	write(t, root, "tools/scan-action/action.yaml", "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: bandit -r . --exit-zero\n")
	if err := os.MkdirAll(filepath.Join(root, "tools", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, _, err := Run([]string{caller}, Options{Cwd: root, NoAutoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 {
		t.Errorf("files = %v", res.Files)
	}
	if len(res.Findings) != 2 {
		t.Errorf("findings = %v", ruleIDs(res))
	}
	var notes []string
	for _, n := range res.Notes {
		notes = append(notes, n.Message)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "nope.yml was not found") || !strings.Contains(joined, "has no action.yml") {
		t.Errorf("notes = %s", joined)
	}
}

func TestLocalReferenceOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	write(t, parent, "outside/action.yml", "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: semgrep ci || true\n")
	wf := write(t, root, ".github/workflows/a.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./../outside\n")
	res, _, err := Run([]string{wf}, Options{Cwd: root, NoAutoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0].Message, "outside the repository") {
		t.Fatalf("files=%v notes=%+v", res.Files, res.Notes)
	}
}

func TestParseErrorsAreCollected(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/bad.yml", "jobs: [\n")
	write(t, root, ".github/workflows/good.yml", swallowWF)
	res, _, err := Run([]string{root}, Options{Cwd: root, NoAutoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.Errors[0].File != ".github/workflows/bad.yml" || !strings.Contains(res.Errors[0].Error(), "invalid YAML") {
		t.Errorf("errors = %+v", res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Errorf("good file not scanned: %v", ruleIDs(res))
	}
}

func TestConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/a.yml", "on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: mytool --no-fail || true\n      - run: trivy fs .\n")
	write(t, root, "legacy/.gitlab-ci.yml", "a:\n  script: [semgrep ci || true]\n")
	write(t, root, ".gatelint.yml", `fail-on: medium
disable-rules: [GL007]
exclude: [legacy]
scanners:
  - id: mytool
    name: MyTool
    commands: [mytool]
    modes:
      - gates-by-default: true
    settings:
      - names: [--no-fail]
        neuter-when: set
        description: never fails
`)
	res, cfg, err := Run([]string{root}, Options{Cwd: root})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "medium" || !strings.HasSuffix(cfg.Path, ".gatelint.yml") {
		t.Errorf("config = %+v", cfg)
	}
	got := strings.Join(ruleIDs(res), ",")
	if got != "GL001,GL006" {
		t.Errorf("findings = %s", got)
	}
	for _, f := range res.Files {
		if strings.HasPrefix(f, "legacy") {
			t.Errorf("excluded file scanned: %s", f)
		}
	}
	// Explicit configuration wins and auto-lookup can be disabled.
	res, _, err = Run([]string{root}, Options{Cwd: root, Config: &Config{}})
	if err != nil || !strings.Contains(strings.Join(ruleIDs(res), ","), "GL007") {
		t.Errorf("explicit config: %v %v", err, ruleIDs(res))
	}
	// Auto lookup from a file argument uses the file's directory.
	cfgDir := filepath.Join(root, ".github", "workflows")
	write(t, root, ".github/workflows/.gatelint.yaml", "disable-rules: [GL001]\n")
	res, _, err = Run([]string{filepath.Join(cfgDir, "a.yml")}, Options{Cwd: root})
	if err != nil || strings.Contains(strings.Join(ruleIDs(res), ","), "GL001") {
		t.Errorf("file-dir config: %v %v", err, ruleIDs(res))
	}
}

func TestLoadConfigErrors(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"unknown-key.yml": "nope: 1\n",
		"fail-on.yml":     "fail-on: critical\n",
		"rule.yml":        "disable-rules: [GL999]\n",
		"scanner.yml":     "scanners: [{id: x}]\n",
		"syntax.yml":      "fail-on: [\n",
	} {
		p := write(t, root, name, body)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := LoadConfig(filepath.Join(root, "missing.yml")); err == nil {
		t.Error("missing config accepted")
	}
	empty := write(t, root, "empty.yml", "")
	if c, err := LoadConfig(empty); err != nil || c.Path != empty {
		t.Errorf("empty config: %v", err)
	}
	write(t, root, "auto/.gatelint.yml", "fail-on: [\n")
	if _, _, err := Run([]string{filepath.Join(root, "auto")}, Options{Cwd: root}); err == nil {
		t.Error("invalid auto config accepted")
	}
	if FindConfig(filepath.Join(root, "none")) != "" {
		t.Error("FindConfig found a file in a missing dir")
	}
}

func TestExcluder(t *testing.T) {
	e := newExcluder([]string{"./legacy", "**/vendor/**", "ci/*.yml", " "})
	for p, want := range map[string]bool{
		"legacy":             true,
		"legacy/a.yml":       true,
		"a/vendor/b/c.yml":   true,
		"ci/a.yml":           true,
		"ci/x/a.yml":         false,
		".github/workflows/": false,
		"legacy2/a.yml":      false,
	} {
		if got := e.match(p); got != want {
			t.Errorf("match(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestRepoFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "trivy.yaml", "exit-code: 1\n")
	p := &model.Pipeline{Root: root}
	if !repoFiles(p, "trivy.yaml") || repoFiles(p, "missing") || repoFiles(&model.Pipeline{}, "trivy.yaml") {
		t.Error("repoFiles")
	}
	if findRoot(filepath.Join(root, "x", "action.yml"), kindAction) == "" {
		t.Error("findRoot fallback")
	}
}
