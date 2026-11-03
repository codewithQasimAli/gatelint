package shell

import (
	"strings"
	"testing"
)

func analyzeDefault(src string) *Result {
	return Analyze(src, GitHubOptions("", false))
}

func only(t *testing.T, r *Result) *Invocation {
	t.Helper()
	if len(r.Invocations) != 1 {
		t.Fatalf("invocations = %d, want 1 (parse error %q)", len(r.Invocations), r.ParseError)
	}
	return r.Invocations[0]
}

func TestSwallowKinds(t *testing.T) {
	cases := []struct {
		src  string
		kind string
		text string
	}{
		{"trivy fs . || true", "or", "|| true"},
		{"trivy fs . || :", "or", "|| :"},
		{"trivy fs . || exit 0", "or", "|| exit 0"},
		{"trivy fs . || printf 'x'", "or", "|| printf 'x'"},
		{"trivy fs . || { echo a; true; }", "or", "|| { echo a; true; }"},
		{"trivy fs . || (echo a)", "or", "|| (echo a)"},
		{"trivy fs . || echo a && true", "or", ""},
		{"trivy fs . || export X=1", "or", ""},
		{"! trivy fs .", "negated", "!"},
		{"trivy fs . &", "background", "&"},
		{"trivy fs . && echo ok\necho next", "and", "&& echo ok"},
		{"if trivy fs .; then echo ok; fi", "if", ""},
		{"while ! trivy fs .; do sleep 1; done", "if", ""},
		{"echo $(trivy fs .)", "subst", "echo"},
		{"local x=$(trivy fs .)", "subst", "local"},
		{"cat <(trivy fs .)", "subst", ""},
	}
	for _, c := range cases {
		t.Run(c.src, func(t *testing.T) {
			inv := only(t, analyzeDefault(c.src))
			if inv.Swallow == nil {
				t.Fatalf("not swallowed")
			}
			if inv.Swallow.Kind != c.kind {
				t.Errorf("kind = %s, want %s", inv.Swallow.Kind, c.kind)
			}
			if c.text != "" && inv.Swallow.Text != c.text {
				t.Errorf("text = %q, want %q", inv.Swallow.Text, c.text)
			}
		})
	}
}

func TestNotSwallowed(t *testing.T) {
	cases := []string{
		"trivy fs .",
		"trivy fs . || exit 1",
		"trivy fs . || exit",
		"trivy fs . || false",
		"trivy fs . || { echo bad; exit 1; }",
		"trivy fs . || rc=$?\nexit $rc",
		"if ! trivy fs .; then exit 1; fi",
		"if trivy fs .; then echo ok; else exit 2; fi",
		"echo start\ntrivy fs . && echo ok",
		"x=$(trivy fs .)",
		"for d in a b; do trivy fs $d; done",
		"case $X in a) trivy fs .;; esac",
		"f() { trivy fs .; }\nf",
		"time trivy fs .",
		"trivy fs . || return 1",
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			r := analyzeDefault(src)
			if len(r.Invocations) == 0 {
				t.Fatal("no invocation found")
			}
			for _, inv := range r.Invocations {
				if inv.Swallow != nil {
					t.Errorf("swallowed as %+v", inv.Swallow)
				}
			}
		})
	}
}

func TestErrexitTracking(t *testing.T) {
	r := analyzeDefault("set +e\ntrivy fs .\nrc=$?\nset -e\ngitleaks detect\nset -euo pipefail\nsemgrep ci | tee x\nset +ex\nbandit -r .")
	if len(r.Invocations) != 4 {
		t.Fatalf("invocations = %d", len(r.Invocations))
	}
	trivy, gitleaks, semgrep, bandit := r.Invocations[0], r.Invocations[1], r.Invocations[2], r.Invocations[3]
	if !trivy.ErrexitOff || trivy.ErrexitLine != 1 || !trivy.StatusChecked || trivy.Last {
		t.Errorf("trivy = %+v", trivy)
	}
	if gitleaks.ErrexitOff {
		t.Errorf("gitleaks errexit should be on")
	}
	if !semgrep.Pipefail || semgrep.PipedInto != "tee" {
		t.Errorf("semgrep = %+v", semgrep)
	}
	if !bandit.ErrexitOff || bandit.ErrexitLine != 8 || !bandit.Last {
		t.Errorf("bandit = %+v", bandit)
	}
	if !strings.Contains(bandit.ErrexitReason, "set +ex") {
		t.Errorf("reason = %q", bandit.ErrexitReason)
	}
}

func TestSetOErrexit(t *testing.T) {
	inv := only(t, analyzeDefault("set +o errexit\ntrivy fs .\necho"))
	if !inv.ErrexitOff {
		t.Fatal("errexit should be off")
	}
	inv = only(t, analyzeDefault("set +e\nset -o errexit\ntrivy fs .\necho"))
	if inv.ErrexitOff {
		t.Fatal("errexit should be back on")
	}
	inv = only(t, analyzeDefault("set -o pipefail\nset +o pipefail\ntrivy fs . | tee x"))
	if inv.Pipefail {
		t.Fatal("pipefail should be off")
	}
}

func TestPositionsAndArgs(t *testing.T) {
	r := analyzeDefault("echo hi\n  sudo -E timeout 10m trivy image --exit-code 1 app:latest")
	inv := only(t, r)
	if inv.Line != 2 || inv.Column != 23 {
		t.Errorf("pos = %d:%d, want 2:23", inv.Line, inv.Column)
	}
	args := inv.Match.Args
	if len(args) != 4 || args[1].Value != "--exit-code" || args[2].Column != 47 {
		t.Errorf("args = %+v", args)
	}
	if len(r.Statements) != 2 || r.Statements[1].Line != 2 {
		t.Errorf("statements = %+v", r.Statements)
	}
}

func TestExpressionsPlaceholders(t *testing.T) {
	opts := GitHubOptions("", false)
	opts.Env = map[string]string{"CODE": "0", "SECRET": "${{ secrets.X }}"}
	r := Analyze(`trivy image "${{ github.repository }}" --exit-code ${{ env.CODE }} --token "$SECRET" --x ${{ inputs.y }}`, opts)
	inv := only(t, r)
	args := inv.Match.Args
	if args[1].Value != "${{ github.repository }}" || args[1].Known {
		t.Errorf("repository arg = %+v", args[1])
	}
	if args[3].Value != "0" || !args[3].Known {
		t.Errorf("env expression not resolved: %+v", args[3])
	}
	if args[7].Known || args[7].Value != "${{ inputs.y }}" {
		t.Errorf("input arg = %+v", args[7])
	}
	if !strings.Contains(r.Statements[0].Text, "${{ env.CODE }}") && !strings.Contains(r.Statements[0].Text, "--exit-code 0") {
		t.Errorf("statement text = %q", r.Statements[0].Text)
	}
	// Columns after an expression stay exact.
	if args[2].Column != 40 {
		t.Errorf("column after expression = %d, want 40", args[2].Column)
	}
}

func TestEnvTracking(t *testing.T) {
	r := analyzeDefault("export TRIVY_EXIT_CODE=0\nCODE=1\ntrivy fs --exit-code $CODE .\nGRYPE_FAIL_ON_SEVERITY=high grype dir:.\ndeclare -x LEVEL=none\nnpm audit --audit-level=$LEVEL")
	if len(r.Invocations) != 3 {
		t.Fatalf("invocations = %d", len(r.Invocations))
	}
	if r.Invocations[0].Env["TRIVY_EXIT_CODE"] != "0" || r.Invocations[0].Match.Args[2].Value != "1" {
		t.Errorf("trivy env/args = %+v %+v", r.Invocations[0].Env, r.Invocations[0].Match.Args)
	}
	if r.Invocations[1].Env["GRYPE_FAIL_ON_SEVERITY"] != "high" {
		t.Errorf("grype env = %+v", r.Invocations[1].Env)
	}
	if r.Invocations[2].Match.Args[0].Value != "--audit-level=none" {
		t.Errorf("npm args = %+v", r.Invocations[2].Match.Args)
	}
}

func TestQuotingAndEscapes(t *testing.T) {
	r := analyzeDefault(`bandit -r 'src dir' "--exit-zero" \--format=json -x "a\"b"`)
	args := only(t, r).Match.Args
	want := []string{"-r", "src dir", "--exit-zero", "--format=json", "-x", `a"b`}
	for i, w := range want {
		if args[i].Value != w || !args[i].Known {
			t.Errorf("arg %d = %+v, want %q", i, args[i], w)
		}
	}
	args = only(t, analyzeDefault("trivy fs $(pwd) ${HOME:-x}")).Match.Args
	if args[1].Known || args[2].Known {
		t.Errorf("expansions should be unknown: %+v", args)
	}
}

func TestNestedShell(t *testing.T) {
	inv := only(t, analyzeDefault(`bash -c "trivy fs . || true"`))
	if inv.Swallow == nil || inv.Swallow.Kind != "or" {
		t.Fatalf("nested swallow = %+v", inv.Swallow)
	}
	if inv.Line != 1 || inv.Column != 10 {
		t.Errorf("nested position = %d:%d", inv.Line, inv.Column)
	}
	inv = only(t, analyzeDefault("sh -c 'trivy fs .; echo done' || true"))
	if inv.Swallow == nil || !inv.ErrexitOff {
		t.Fatalf("nested context lost: %+v", inv)
	}
	inv = only(t, analyzeDefault("bash -ec 'trivy fs .; echo done'"))
	if inv.ErrexitOff {
		t.Fatal("bash -ec enables errexit")
	}
	if r := analyzeDefault(`bash -c "$SCRIPT"`); len(r.Invocations) != 0 {
		t.Fatal("unknown nested script should not match")
	}
	inv = only(t, analyzeDefault(`bash -o pipefail -c "trivy fs . | tee x"`))
	if inv.PipedInto != "tee" {
		t.Fatalf("piped = %q", inv.PipedInto)
	}
}

func TestNotScanners(t *testing.T) {
	for _, src := range []string{
		"echo trivy fs .",
		"pip install bandit semgrep",
		"apt-get install -y trivy",
		"trivy --version",
		"semgrep login",
		"npm audit fix",
		"# trivy fs . || true",
		"brew install gitleaks || true",
	} {
		if r := analyzeDefault(src); len(r.Invocations) != 0 {
			t.Errorf("%q matched %s", src, r.Invocations[0].Match.Tool.ID)
		}
	}
}

func TestFallback(t *testing.T) {
	src := "echo \"unterminated\nset +e\ntrivy fs --exit-code 1 . || true\ngitleaks detect | tee x # comment\nbandit -r .\nrc=$?"
	r := analyzeDefault(src)
	if !r.Fallback || r.ParseError == "" {
		t.Fatalf("expected fallback, got %+v", r)
	}
	if len(r.Invocations) != 3 {
		t.Fatalf("invocations = %d", len(r.Invocations))
	}
	trivy, gitleaks, bandit := r.Invocations[0], r.Invocations[1], r.Invocations[2]
	if trivy.Swallow == nil || !trivy.Fallback || !trivy.ErrexitOff || trivy.ErrexitLine != 2 {
		t.Errorf("trivy = %+v", trivy)
	}
	if gitleaks.PipedInto != "tee" {
		t.Errorf("gitleaks piped = %q", gitleaks.PipedInto)
	}
	if !bandit.StatusChecked {
		t.Errorf("bandit status should be checked")
	}
	if trivy.Line != 3 || trivy.Column != 1 {
		t.Errorf("trivy pos = %d:%d", trivy.Line, trivy.Column)
	}
}

func TestFallbackLastAndErrexitRestore(t *testing.T) {
	r := analyzeDefault("echo 'x\nset +e\nset -e\ntrivy fs .")
	inv := only(t, r)
	if inv.ErrexitOff || !inv.Last {
		t.Errorf("inv = %+v", inv)
	}
}

func TestPowerShellUsesHeuristics(t *testing.T) {
	r := Analyze("trivy fs --exit-code 0 .\nbandit -r src || Write-Host failed", GitHubOptions("", true))
	if !r.Fallback || len(r.Invocations) != 2 {
		t.Fatalf("result = %+v", r)
	}
	if r.Invocations[0].ErrexitOff {
		t.Error("pwsh should not report errexit")
	}
	if r.Invocations[1].Swallow == nil {
		t.Error("Write-Host swallow not detected")
	}
}

func TestPOSIXFallsBackToBashParser(t *testing.T) {
	inv := only(t, Analyze("[[ -n x ]] && echo\ntrivy fs . || true", GitHubOptions("sh", false)))
	if inv.Fallback {
		t.Error("bash parser should accept the script")
	}
}

func TestGitHubOptions(t *testing.T) {
	cases := []struct {
		shell             string
		windows           bool
		dialect           Dialect
		errexit, pipefail bool
	}{
		{"", false, Bash, true, false},
		{"", true, PowerShell, true, true},
		{"bash", false, Bash, true, true},
		{"sh", false, POSIX, true, false},
		{"pwsh", false, PowerShell, true, true},
		{"python", false, Other, true, true},
		{"cmd", true, Other, true, true},
		{"bash {0}", false, Bash, false, false},
		{"bash -e {0}", false, Bash, true, false},
		{"bash -eo pipefail {0}", false, Bash, true, true},
		{"bash --noprofile --norc -o errexit -o pipefail {0}", false, Bash, true, true},
		{"/bin/sh -ex {0}", false, POSIX, true, false},
		{"pwsh -command \". '{0}'\"", false, PowerShell, true, true},
		{"perl {0}", false, Other, true, true},
	}
	for _, c := range cases {
		o := GitHubOptions(c.shell, c.windows)
		if o.Dialect != c.dialect || o.Errexit != c.errexit || o.Pipefail != c.pipefail {
			t.Errorf("%q: got dialect=%d errexit=%v pipefail=%v", c.shell, o.Dialect, o.Errexit, o.Pipefail)
		}
	}
	if o := CustomOptions(""); o.Dialect != Bash || !o.Errexit {
		t.Errorf("empty custom shell = %+v", o)
	}
	g := GitLabOptions()
	if !g.Errexit || !g.Pipefail {
		t.Errorf("gitlab options = %+v", g)
	}
}

func TestShellWithoutErrexitReason(t *testing.T) {
	inv := only(t, Analyze("gitleaks detect\necho", GitHubOptions("bash {0}", false)))
	if !inv.ErrexitOff || !strings.Contains(inv.ErrexitReason, "bash {0}") {
		t.Fatalf("inv = %+v", inv)
	}
	inv = only(t, Analyze("gitleaks detect\necho", Options{Dialect: Bash}))
	if inv.ErrexitReason != "the shell runs without errexit" {
		t.Fatalf("reason = %q", inv.ErrexitReason)
	}
}

func TestUnescape(t *testing.T) {
	if got := unescape(`a\ b\\c`, false); got != `a b\c` {
		t.Errorf("unquoted = %q", got)
	}
	if got := unescape(`a\nb\"c`, true); got != `a\nb"c` {
		t.Errorf("quoted = %q", got)
	}
	if got := unescape("a\\\nb", false); got != "ab" {
		t.Errorf("line continuation = %q", got)
	}
}

func TestOutputs(t *testing.T) {
	inv := only(t, analyzeDefault("trivy fs . > report.txt 2>/dev/null || true"))
	if len(inv.Outputs) != 1 || inv.Outputs[0] != "report.txt" {
		t.Errorf("redirect outputs = %v", inv.Outputs)
	}
	inv = only(t, analyzeDefault("gitleaks detect | tee -a leaks.txt /dev/stderr"))
	if len(inv.Outputs) != 1 || inv.Outputs[0] != "leaks.txt" {
		t.Errorf("tee outputs = %v", inv.Outputs)
	}
	inv = only(t, analyzeDefault("semgrep ci >> a.json &> b.json"))
	if len(inv.Outputs) != 2 {
		t.Errorf("append/all outputs = %v", inv.Outputs)
	}
}
