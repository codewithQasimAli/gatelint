package github

import (
	"strings"
	"testing"
)

func TestParseWorkflow(t *testing.T) {
	src := `name: ci
on: push
env:
  GLOBAL: "1"
defaults:
  run:
    shell: sh
x-anchors:
  step: &checkout
    uses: actions/checkout@v4
jobs:
  build:
    name: Build and scan
    runs-on: [self-hosted, linux]
    if: github.ref == 'refs/heads/main'
    continue-on-error: ${{ matrix.experimental }}
    env:
      JOB: two
    steps:
      - *checkout
      - name: Scan
        id: scan
        shell: bash
        env:
          STEP: three
        with:
          ignored: true
        run: |
          echo start
            trivy fs --exit-code 1 .
      - id: only-id
        run: echo hi
      - run: "   "
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          exit-code: '0'
          args: |
            --one
            --two
      - "not a mapping"
  windows:
    runs-on:
      labels: [windows-latest]
      group: big
    defaults:
      run:
        shell: pwsh
    steps:
      - run: trivy fs .
  reusable:
    uses: ./.github/workflows/scan.yml
  remote:
    uses: org/repo/.github/workflows/scan.yml@v1
  not-a-job: 42
`
	p, err := Parse(".github/workflows/ci.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != "workflow" || len(p.Jobs) != 4 {
		t.Fatalf("kind=%s jobs=%d", p.Kind, len(p.Jobs))
	}
	if p.Env["GLOBAL"].Raw != "1" {
		t.Errorf("workflow env = %+v", p.Env)
	}
	b := p.Jobs[0]
	if b.ID != "build" || b.Name != "Build and scan" || b.RunsOn != "self-hosted,linux" || b.DefaultShell.Raw != "sh" {
		t.Errorf("job = %+v", b)
	}
	if !b.ContinueOnError.IsExpression() || b.If.Raw == "" || b.Env["JOB"].Raw != "two" {
		t.Errorf("job fields = %+v", b)
	}
	if len(b.Steps) != 5 {
		t.Fatalf("steps = %d", len(b.Steps))
	}
	if b.Steps[0].Uses.Raw != "actions/checkout@v4" || b.Steps[0].Name != "actions/checkout@v4" {
		t.Errorf("aliased step = %+v", b.Steps[0])
	}
	scan := b.Steps[1]
	if scan.Name != "Scan" || scan.Shell.Raw != "bash" || scan.Env["STEP"].Raw != "three" {
		t.Errorf("scan step = %+v", scan)
	}
	seg := scan.Run.Segments[0]
	if seg.Pos.Line != 29 || seg.Pos.Column != 11 || seg.ContColumn != 11 {
		t.Errorf("block scalar segment pos = %+v cont=%d", seg.Pos, seg.ContColumn)
	}
	if !strings.HasPrefix(seg.Text, "echo start\n  trivy") {
		t.Errorf("segment text = %q", seg.Text)
	}
	if b.Steps[2].Name != "only-id" || b.Steps[3].Name != "step 4" {
		t.Errorf("step names = %q %q", b.Steps[2].Name, b.Steps[3].Name)
	}
	action := b.Steps[4]
	if v, ok := action.Input("EXIT-CODE"); !ok || v.Raw != "0" || v.Pos.Line != 36 {
		t.Errorf("input = %+v %v", v, ok)
	}
	if _, ok := action.Input("missing"); ok {
		t.Error("missing input found")
	}
	if p.Jobs[1].RunsOn != "windows-latest,big" || p.Jobs[1].DefaultShell.Raw != "pwsh" {
		t.Errorf("windows job = %+v", p.Jobs[1])
	}
	if len(p.LocalRefs) != 1 || p.LocalRefs[0] != ".github/workflows/scan.yml" {
		t.Errorf("local refs = %v", p.LocalRefs)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0].Message, "out of scope") {
		t.Errorf("notes = %+v", p.Notes)
	}
}

func TestStepNameTruncation(t *testing.T) {
	p, err := Parse("w.yml", []byte("jobs:\n  a:\n    steps:\n      - run: echo this is a very long command line that goes on and on\n"))
	if err != nil {
		t.Fatal(err)
	}
	name := p.Jobs[0].Steps[0].Name
	if !strings.HasPrefix(name, "run: echo this") || !strings.HasSuffix(name, "...") || len(name) > 45 {
		t.Errorf("name = %q", name)
	}
}

func TestPlainAndQuotedRunPositions(t *testing.T) {
	p, err := Parse("w.yml", []byte("jobs:\n  a:\n    steps:\n      - run: trivy fs .\n      - run: \"trivy fs .\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s := p.Jobs[0].Steps[0].Run.Segments[0]; s.Pos.Line != 4 || s.Pos.Column != 14 {
		t.Errorf("plain = %+v", s.Pos)
	}
	if s := p.Jobs[0].Steps[1].Run.Segments[0]; s.Pos.Line != 5 || s.Pos.Column != 15 {
		t.Errorf("quoted = %+v", s.Pos)
	}
}

func TestCompositeAction(t *testing.T) {
	src := "name: My action\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: bandit -r .\n    - uses: ./.github/actions/inner/\n"
	p, err := Parse(".github/actions/x/action.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != "composite-action" || len(p.Jobs) != 1 || p.Jobs[0].Name != "My action" || len(p.Jobs[0].Steps) != 2 {
		t.Fatalf("composite = %+v", p)
	}
	if len(p.LocalRefs) != 1 || p.LocalRefs[0] != ".github/actions/inner" {
		t.Errorf("refs = %v", p.LocalRefs)
	}
	for _, src := range []string{"runs:\n  using: node20\n  main: index.js\n", "runs:\n  using: docker\n  image: Dockerfile\n"} {
		p, err := Parse("action.yml", []byte(src))
		if err != nil || len(p.Jobs) != 0 {
			t.Errorf("non-composite action: %v %+v", err, p)
		}
	}
	if !IsActionFile(`C:\repo\action.yaml`) || IsActionFile("actions.yml") {
		t.Error("IsActionFile")
	}
}

func TestEmptyAndOddWorkflows(t *testing.T) {
	for _, src := range []string{"", "# only a comment\n", "~\n", "on: push\n", "jobs:\n"} {
		p, err := Parse("w.yml", []byte(src))
		if err != nil || len(p.Jobs) != 0 {
			t.Errorf("%q: err=%v jobs=%d", src, err, len(p.Jobs))
		}
	}
	p, err := Parse("w.yml", []byte("jobs: [a, b]\n"))
	if err != nil || len(p.Notes) != 1 {
		t.Errorf("jobs list: err=%v notes=%v", err, p.Notes)
	}
	p, err = Parse("w.yml", []byte("jobs:\n  a:\n    steps: run\n"))
	if err != nil || len(p.Notes) != 1 {
		t.Errorf("steps scalar: err=%v notes=%v", err, p.Notes)
	}
}

func TestMalformed(t *testing.T) {
	cases := map[string]string{
		"tabs":       "on: push\njobs:\n  scan:\n\truns-on: ubuntu-latest\n",
		"unclosed":   "jobs: [a\n",
		"not a map":  "- a\n- b\n",
		"bad scalar": "jobs:\n  a: *missing\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse("w.yml", []byte(src))
			if err == nil {
				t.Fatal("expected an error")
			}
			if name == "tabs" && !strings.Contains(err.Error(), "tab characters") {
				t.Errorf("tab hint missing: %v", err)
			}
		})
	}
}

func TestCRLF(t *testing.T) {
	src := "jobs:\r\n  a:\r\n    steps:\r\n      - run: |\r\n          echo hi\r\n          trivy fs .\r\n"
	p, err := Parse("w.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	seg := p.Jobs[0].Steps[0].Run.Segments[0]
	if strings.Contains(seg.Text, "\r") || seg.Pos.Line != 5 {
		t.Errorf("segment = %+v", seg)
	}
}
