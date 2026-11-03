package gitlab

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

func parse(t *testing.T, src string) *model.Pipeline {
	t.Helper()
	p, err := Parse(".gitlab-ci.yml", []byte(src), Options{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func job(t *testing.T, p *model.Pipeline, name string) *model.Job {
	t.Helper()
	for _, j := range p.Jobs {
		if j.ID == name {
			return j
		}
	}
	t.Fatalf("job %s not found in %d jobs", name, len(p.Jobs))
	return nil
}

func scriptText(j *model.Job, section string) string {
	var parts []string
	for _, s := range j.Scripts {
		if s.Section == section {
			for _, seg := range s.Segments {
				parts = append(parts, seg.Text)
			}
		}
	}
	return strings.Join(parts, "|")
}

func TestJobsAndKeywords(t *testing.T) {
	p := parse(t, `stages: [test]
variables:
  GLOBAL: g
  OBJ:
    value: v
    description: d
image: alpine
default:
  before_script:
    - echo default
.hidden:
  script: [echo hidden]
test:
  image:
    name: python:3.12
  variables:
    LOCAL: l
  script:
    - echo one
    - - nested
      - list
    - |
      multi
      line
  after_script: echo after
  allow_failure:
    exit_codes: [1, "137"]
  when: manual
  rules:
    - if: $CI
      when: never
      allow_failure: true
    - when: on_success
    - not-a-map
plain:
  script: echo plain
  allow_failure: true
trigger-job:
  trigger: other/project
noinherit:
  inherit:
    default: false
    variables: false
  script: [echo x]
partial:
  inherit:
    default: [image]
  script: [echo y]
`)
	if len(p.Jobs) != 4 {
		t.Fatalf("jobs = %d", len(p.Jobs))
	}
	j := job(t, p, "test")
	if j.Image != "python:3.12" || j.Env["GLOBAL"].Raw != "g" || j.Env["OBJ"].Raw != "v" || j.Env["LOCAL"].Raw != "l" {
		t.Errorf("job fields = %+v", j)
	}
	if got := scriptText(j, "before_script"); got != "echo default" {
		t.Errorf("before_script = %q", got)
	}
	if got := scriptText(j, "script"); got != "echo one|nested|list|multi\nline\n" {
		t.Errorf("script = %q", got)
	}
	if got := scriptText(j, "after_script"); got != "echo after" {
		t.Errorf("after_script = %q", got)
	}
	if !j.AllowFailure.Set || j.AllowFailure.Bool || len(j.AllowFailure.ExitCodes) != 2 || j.AllowFailure.ExitCodes[1] != 137 {
		t.Errorf("allow_failure = %+v", j.AllowFailure)
	}
	if j.When.Raw != "manual" || len(j.Rules) != 2 || j.Rules[0].When.Raw != "never" || !j.Rules[0].AllowFailure.Bool || j.Rules[0].If != "$CI" {
		t.Errorf("when/rules = %+v %+v", j.When, j.Rules)
	}
	// Block scalar positions inside a script list.
	for _, s := range j.Scripts {
		if s.Section == "script" {
			if seg := s.Segments[3]; seg.Pos.Line != 23 || seg.Pos.Column != 7 {
				t.Errorf("block item pos = %+v", seg.Pos)
			}
		}
	}
	pl := job(t, p, "plain")
	if !pl.AllowFailure.Bool || pl.Image != "alpine" {
		t.Errorf("plain = %+v", pl)
	}
	ni := job(t, p, "noinherit")
	if scriptText(ni, "before_script") != "" || len(ni.Env) != 0 || ni.Image != "" {
		t.Errorf("inherit false = %+v", ni)
	}
	pa := job(t, p, "partial")
	if scriptText(pa, "before_script") != "" || pa.Image != "alpine" {
		t.Errorf("inherit list = %+v", pa)
	}
}

func TestAnchorsExtendsReference(t *testing.T) {
	p := parse(t, `.base: &base
  image: base:1
  variables:
    A: "1"
    B: "1"
  script:
    - echo base
.middle:
  extends: .base
  variables:
    B: "2"
.setup:
  script:
    - set +e
    - echo setup
child:
  extends: [.middle, .missing]
  variables:
    C: "3"
  script:
    - !reference [.setup, script]
    - trivy fs .
anchored:
  <<: *base
  script: [echo anchored]
broken:
  script:
    - !reference [.nope, script]
    - !reference [single]
    - echo ok
cycle-a:
  extends: cycle-b
  script: [echo a]
cycle-b:
  extends: cycle-a
  script: [echo b]
`)
	c := job(t, p, "child")
	if c.Image != "base:1" || c.Env["A"].Raw != "1" || c.Env["B"].Raw != "2" || c.Env["C"].Raw != "3" {
		t.Errorf("extends merge = %+v", c)
	}
	if got := scriptText(c, "script"); got != "set +e|echo setup|trivy fs ." {
		t.Errorf("reference script = %q", got)
	}
	if a := job(t, p, "anchored"); a.Image != "base:1" || scriptText(a, "script") != "echo anchored" {
		t.Errorf("anchored = %+v", a)
	}
	if got := scriptText(job(t, p, "broken"), "script"); got != "echo ok" {
		t.Errorf("broken = %q", got)
	}
	job(t, p, "cycle-a")
	var msgs []string
	for _, n := range p.Notes {
		msgs = append(msgs, n.Message)
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"unknown job \".missing\"", "[.nope, script]", "malformed", "cyclic"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes missing %q:\n%s", want, joined)
		}
	}
}

func TestIncludes(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ci/a.yml", "include: ci/nested/b.yml\njob-a:\n  script: [echo a]\nshared:\n  script: [echo from-include]\n  variables:\n    X: inc\n")
	write("ci/nested/b.yml", "job-b:\n  script: [echo b]\n")
	write("ci/glob/one.yml", "glob-one:\n  script: [echo 1]\n")
	write("ci/glob/deep/two.yml", "glob-two:\n  script: [echo 2]\n")
	write("ci/bad.yml", "x: [\n")
	main := `include:
  - local: /ci/a.yml
  - ci/a.yml
  - local: 'ci/glob/*.yml'
  - local: ci/glob/**/two.yml
  - local: ci/bad.yml
  - local: $DIR/x.yml
  - local: ""
  - https://example.com/remote.yml
  - remote: https://example.com/other.yml
  - project: group/project
    file: x.yml
  - template: Jobs/SAST.gitlab-ci.yml
  - component: gitlab.com/components/sast/sast@1
shared:
  variables:
    Y: main
`
	var displayed []string
	p, err := Parse(".gitlab-ci.yml", []byte(main), Options{Root: root, Display: func(s string) string {
		rel, _ := filepath.Rel(root, s)
		displayed = append(displayed, rel)
		return filepath.ToSlash(rel)
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"job-a", "job-b", "glob-one", "glob-two", "shared"} {
		job(t, p, name)
	}
	s := job(t, p, "shared")
	if s.Env["X"].Raw != "inc" || s.Env["Y"].Raw != "main" || scriptText(s, "script") != "echo from-include" {
		t.Errorf("deep merge of include = %+v", s)
	}
	if s.Env["X"].Pos.File != "ci/a.yml" {
		t.Errorf("included variable keeps its file: %+v", s.Env["X"].Pos)
	}
	if len(p.Templates) != 2 {
		t.Errorf("templates = %+v", p.Templates)
	}
	if len(p.Files) != 5 {
		t.Errorf("files = %v", p.Files)
	}
	var msgs []string
	for _, n := range p.Notes {
		msgs = append(msgs, n.Message)
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"ci/bad.yml", "uses variables", "remote include https://example.com/remote.yml", "remote include https://example.com/other.yml", "project group/project"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes missing %q:\n%s", want, joined)
		}
	}
}

func TestIncludeOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.yml"), []byte("leak:\n  script: [semgrep ci || true]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Parse(".gitlab-ci.yml", []byte("include:\n  - local: ../secret.yml\n  - local: /../secret.yml\n  - local: ci/../../secret.yml\n"), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Jobs) != 0 || len(p.Notes) != 3 || !strings.Contains(p.Notes[0].Message, "outside the repository") {
		t.Fatalf("jobs=%d notes=%+v", len(p.Jobs), p.Notes)
	}
}

func TestIncludeReadError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "x.yml"), []byte("a:\n  script: [b]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Parse(".gitlab-ci.yml", []byte("include: x.yml\nmissing-file:\n  script: [echo]\n"), Options{
		Root:     root,
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("denied") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0].Message, "denied") {
		t.Errorf("notes = %+v", p.Notes)
	}
}

func TestMalformedAndEmpty(t *testing.T) {
	if _, err := Parse("x", []byte("a: [\n"), Options{}); err == nil {
		t.Error("expected parse error")
	}
	if _, err := Parse("x", []byte("- a\n"), Options{}); err == nil {
		t.Error("expected not-a-mapping error")
	}
	for _, src := range []string{"", "# comment\n", "stages: [a]\n"} {
		p, err := Parse("x", []byte(src), Options{})
		if err != nil || len(p.Jobs) != 0 {
			t.Errorf("%q: %v %+v", src, err, p)
		}
	}
}

func TestGlobRegexp(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"ci/*.yml", "ci/a.yml", true},
		{"ci/*.yml", "ci/x/a.yml", false},
		{"ci/**/*.yml", "ci/x/y/a.yml", true},
		{"ci/**.yml", "ci/x/a.yml", true},
		{"ci/?.yml", "ci/a.yml", true},
		{"ci/a.yml", "ci/a.yml", true},
	}
	for _, c := range cases {
		if got := globRegexp(c.pattern).MatchString(c.path); got != c.want {
			t.Errorf("%s ~ %s = %v", c.pattern, c.path, got)
		}
	}
}
