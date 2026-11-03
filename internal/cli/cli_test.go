package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr, BuildInfo{Version: "1.0.0", Commit: "abc123", Date: "2026-01-01"})
	return code, stdout.String(), stderr.String()
}

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const wf = "on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: trivy fs .\n      - run: semgrep ci\n        continue-on-error: ${{ matrix.x }}\n"

func TestExitCodes(t *testing.T) {
	clean := tree(t, map[string]string{".github/workflows/a.yml": "on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: semgrep ci\n"})
	medium := tree(t, map[string]string{".github/workflows/a.yml": wf})
	high := tree(t, map[string]string{".gitlab-ci.yml": "a:\n  script: [semgrep ci || true]\n"})
	broken := tree(t, map[string]string{".gitlab-ci.yml": "a: [\n"})
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"scan", clean}, ExitOK},
		{[]string{"scan", medium}, ExitOK},
		{[]string{"scan", medium, "--fail-on", "medium"}, ExitFindings},
		{[]string{"scan", medium, "--fail-on", "low"}, ExitFindings},
		{[]string{"scan", high}, ExitFindings},
		{[]string{"scan", high, "--fail-on", "none"}, ExitOK},
		{[]string{"scan", high, "--fail-on", "HIGH"}, ExitFindings},
		{[]string{"scan", broken}, ExitError},
		{[]string{"scan", filepath.Join(clean, "missing")}, ExitError},
		{[]string{"scan", clean, "--format", "xml"}, ExitError},
		{[]string{"scan", clean, "--fail-on", "critical"}, ExitError},
		{[]string{"scan", clean, "--platform", "jenkins"}, ExitError},
		{[]string{"scan", clean, "--config", filepath.Join(clean, "nope.yml")}, ExitError},
		{[]string{"scan", "--bogus"}, ExitError},
		{[]string{"nonsense"}, ExitError},
		{[]string{"rules", "GL999"}, ExitError},
		{[]string{"version", "extra"}, ExitError},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, _, stderr := run(t, c.args...)
			if code != c.code {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, c.code, stderr)
			}
			if c.code == ExitError && stderr == "" {
				t.Error("no error message on stderr")
			}
		})
	}
}

func TestDefaultPathIsCwd(t *testing.T) {
	dir := tree(t, map[string]string{".gitlab-ci.yml": "a:\n  script: [semgrep ci || true]\n"})
	t.Chdir(dir)
	code, out, _ := run(t, "scan", "--no-color")
	if code != ExitFindings || !strings.Contains(out, ".gitlab-ci.yml:2") {
		t.Errorf("code=%d out=%s", code, out)
	}
}

func TestOutputFileAndFormats(t *testing.T) {
	dir := tree(t, map[string]string{".github/workflows/a.yml": wf})
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, stdout, _ := run(t, "scan", dir, "--format", "sarif", "--output", out)
	if code != ExitOK || stdout != "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil || !json.Valid(data) || !strings.Contains(string(data), `"version": "1.0.0"`) {
		t.Fatalf("sarif file: %v %s", err, data)
	}
	for _, f := range []string{"json", "codequality", "table"} {
		code, stdout, _ := run(t, "scan", dir, "--format", f, "--quiet")
		if code != ExitOK || stdout == "" {
			t.Errorf("%s: code=%d", f, code)
		}
	}
	if code, _, stderr := run(t, "scan", dir, "--output", filepath.Join(dir, "missing", "x.json")); code != ExitError || stderr == "" {
		t.Errorf("unwritable output: code=%d", code)
	}
}

func TestConfigFlagAndFailOnFromConfig(t *testing.T) {
	dir := tree(t, map[string]string{
		".github/workflows/a.yml": wf,
		".gatelint.yml":           "fail-on: medium\n",
		"other.yml":               "disable-rules: [GL004, GL007]\n",
	})
	if code, _, _ := run(t, "scan", dir); code != ExitFindings {
		t.Errorf("config fail-on medium: code=%d", code)
	}
	if code, _, _ := run(t, "scan", dir, "--fail-on", "high"); code != ExitOK {
		t.Errorf("flag overrides config: code=%d", code)
	}
	code, out, _ := run(t, "scan", dir, "--config", filepath.Join(dir, "other.yml"), "--fail-on", "low")
	if code != ExitOK || !strings.Contains(out, "No findings.") {
		t.Errorf("--config: code=%d out=%s", code, out)
	}
}

func TestParseErrorReported(t *testing.T) {
	dir := tree(t, map[string]string{".gitlab-ci.yml": "a:\n\tb: 1\n", ".github/workflows/ok.yml": wf})
	code, out, stderr := run(t, "scan", dir)
	if code != ExitError || !strings.Contains(stderr, "tab characters") || !strings.Contains(out, "Summary") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestMalformedFixtures(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, dir := range []string{"testdata/malformed/github", "testdata/malformed/gitlab"} {
		code, _, stderr := run(t, "scan", dir)
		if code != ExitError || !strings.Contains(stderr, "invalid YAML") {
			t.Errorf("%s: code=%d stderr=%q", dir, code, stderr)
		}
	}
}

func TestRepositoryDogfood(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	code, out, stderr := run(t, "scan", ".")
	if code != ExitOK {
		t.Errorf("gatelint scan . = %d\n%s%s", code, out, stderr)
	}
}

func TestRulesAndVersion(t *testing.T) {
	code, out, _ := run(t, "rules")
	if code != ExitOK || !strings.Contains(out, "GL001") || !strings.Contains(out, "GL010") || !strings.Contains(out, "SEVERITY") {
		t.Errorf("rules: %d %s", code, out)
	}
	code, out, _ = run(t, "rules", "gl003")
	if code != ExitOK || !strings.Contains(out, "Scanner piped without pipefail") || !strings.Contains(out, "Before:") || !strings.Contains(out, "docs/rules/GL003.md") {
		t.Errorf("rules GL003: %s", out)
	}
	code, out, _ = run(t, "version")
	if code != ExitOK || out != "gatelint 1.0.0\ncommit: abc123\nbuilt:  2026-01-01\n" {
		t.Errorf("version = %q", out)
	}
	code, out, _ = run(t, "--help")
	if code != ExitOK || !strings.Contains(out, "scan") {
		t.Errorf("help: %s", out)
	}
}

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.1.0": true, "v1.2.3-rc.1": true, "": false, "(devel)": false,
		"v0.0.0-20261103202011-1a3f2629e9bc+dirty": false, "v0.1.1-0.20261103202011-1a3f2629e9bc": false,
	} {
		if got := isRelease(v); got != want {
			t.Errorf("isRelease(%q) = %v", v, got)
		}
	}
}

func TestBuildInfoDefaults(t *testing.T) {
	b := BuildInfo{}.resolve()
	if b.Version == "" || b.Commit != "none" || b.Date != "unknown" {
		t.Errorf("defaults = %+v", b)
	}
	if (&exitError{code: 1}).Error() != "" {
		t.Error("empty exitError message")
	}
}

func TestColorOnlyOnTerminal(t *testing.T) {
	dir := tree(t, map[string]string{".gitlab-ci.yml": "a:\n  script: [semgrep ci || true]\n"})
	old := IsTerminal
	t.Cleanup(func() { IsTerminal = old })
	IsTerminal = func(io.Writer) bool { return true }
	t.Setenv("NO_COLOR", "")
	_, out, _ := run(t, "scan", dir)
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected color on a terminal")
	}
	_, out, _ = run(t, "scan", dir, "--no-color")
	if strings.Contains(out, "\x1b[") {
		t.Error("--no-color ignored")
	}
	t.Setenv("NO_COLOR", "1")
	_, out, _ = run(t, "scan", dir)
	if strings.Contains(out, "\x1b[") {
		t.Error("NO_COLOR ignored")
	}
	if IsTerminal = old; IsTerminal(&bytes.Buffer{}) {
		t.Error("buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if IsTerminal(f) {
		t.Error("regular file is not a terminal")
	}
}
