package rules_test

import (
	"strings"
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
	"github.com/codewithQasimAli/gatelint/internal/github"
	"github.com/codewithQasimAli/gatelint/internal/gitlab"
	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/rules"
	"github.com/codewithQasimAli/gatelint/internal/suppress"
)

const (
	gh = "github"
	gl = "gitlab"
)

// analyze parses one file and runs every rule on it.
func analyze(t *testing.T, platform, src string) ([]model.Finding, *rules.Context) {
	t.Helper()
	var p *model.Pipeline
	var err error
	file := "ci.yml"
	if platform == gh {
		p, err = github.Parse(file, []byte(src))
	} else {
		file = ".gitlab-ci.yml"
		p, err = gitlab.Parse(file, []byte(src), gitlab.Options{Root: t.TempDir()})
	}
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := &rules.Context{
		Catalog:    catalog.Default(),
		Pipelines:  []*model.Pipeline{p},
		Directives: map[string][]suppress.Directive{file: suppress.Parse(file, []byte(src))},
	}
	rules.Collect(ctx, nil)
	fs := rules.Run(ctx)
	suppress.Apply(fs, ctx.Directives, rules.Exempt)
	return fs, ctx
}

func ghSteps(steps string) string {
	return "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n" + indentLines(steps, "      ")
}

func indentLines(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

type ruleCase struct {
	name     string
	platform string
	src      string
	want     int            // number of unsuppressed findings for the rule
	sev      model.Severity // checked when want > 0 and sev >= 0
	line     int            // checked when non-zero (first finding)
}

func runCases(t *testing.T, rule string, cases []ruleCase) {
	t.Helper()
	tp, fp := 0, 0
	for _, c := range cases {
		if c.want > 0 {
			tp++
		} else {
			fp++
		}
		t.Run(c.name, func(t *testing.T) {
			fs, _ := analyze(t, c.platform, c.src)
			var got []model.Finding
			for _, f := range fs {
				if f.RuleID == rule && !f.Suppressed {
					got = append(got, f)
				}
			}
			if len(got) != c.want {
				t.Fatalf("%s findings = %d, want %d: %+v", rule, len(got), c.want, got)
			}
			if c.want > 0 && c.sev >= 0 && got[0].Severity != c.sev {
				t.Errorf("severity = %v, want %v", got[0].Severity, c.sev)
			}
			if c.line > 0 && got[0].Line != c.line {
				t.Errorf("line = %d, want %d", got[0].Line, c.line)
			}
			for _, f := range got {
				if f.Message == "" || f.Hint == "" || f.Title == "" || f.Fingerprint == "" {
					t.Errorf("incomplete finding: %+v", f)
				}
			}
		})
	}
	if tp < 3 || fp < 2 {
		t.Errorf("%s needs at least 3 true-positive and 2 false-positive cases, has %d and %d", rule, tp, fp)
	}
}

func TestGL001(t *testing.T) {
	runCases(t, "GL001", []ruleCase{
		{"or true", gh, ghSteps("- run: trivy fs --exit-code 1 . || true"), 1, model.High, 6},
		{"or colon", gh, ghSteps("- run: 'gitleaks detect || :'"), 1, model.High, 0},
		{"or echo block", gh, ghSteps("- run: |\n    echo start\n    bandit -r src || echo failed"), 1, model.High, 8},
		{"or exit 0", gl, "scan:\n  script:\n    - tfsec . || exit 0\n", 1, model.High, 3},
		{"negated", gh, ghSteps("- run: '! semgrep ci'"), 1, model.High, 0},
		{"and list middle", gl, "scan:\n  script:\n    - checkov -d . && echo ok\n    - echo next\n", 1, model.High, 0},
		{"if no failing branch", gh, ghSteps("- run: |\n    if ! snyk test; then\n      echo bad\n    fi"), 1, model.High, 0},
		{"command substitution", gh, ghSteps("- run: echo \"$(npm audit)\""), 1, model.High, 0},
		{"background", gh, ghSteps("- run: |\n    pip-audit &\n    wait"), 1, model.High, 0},
		{"subshell or true", gh, ghSteps("- run: (cd app && grype dir:. --fail-on high) || true"), 1, model.High, 0},
		{"pipeline or true", gh, ghSteps("- run: trivy fs --exit-code 1 . | tee out || true"), 1, model.High, 0},
		{"bash -c or true", gh, ghSteps("- run: bash -c 'gitleaks detect || true'"), 1, model.High, 0},
		{"unused status capture", gh, ghSteps("- run: |\n    gitleaks detect || rc=$?\n    echo done"), 1, model.High, 0},
		{"non-scanner or true", gh, ghSteps("- run: npm ci || true"), 0, -1, 0},
		{"echo mentions scanner", gh, ghSteps("- run: echo \"trivy found nothing\" || true"), 0, -1, 0},
		{"or exit 1", gl, "scan:\n  script:\n    - trivy fs --exit-code 1 . || exit 1\n", 0, -1, 0},
		{"or block exits", gh, ghSteps("- run: 'gitleaks detect || { echo leaks; exit 1; }'"), 0, -1, 0},
		{"status used later", gh, ghSteps("- run: |\n    gitleaks detect || rc=$?\n    exit ${rc:-0}"), 0, -1, 0},
		{"if with exit", gh, ghSteps("- run: |\n    if ! gitleaks detect; then\n      exit 1\n    fi"), 0, -1, 0},
		{"and list last", gl, "scan:\n  script:\n    - echo start\n    - semgrep ci && echo ok\n", 0, -1, 0},
		{"assignment from substitution", gh, ghSteps("- run: |\n    out=$(semgrep ci)\n    echo \"$out\""), 0, -1, 0},
		{"snyk monitor is not a gate", gh, ghSteps("- run: snyk monitor || true"), 0, -1, 0},
	})
}

func TestGL002(t *testing.T) {
	runCases(t, "GL002", []ruleCase{
		{"set +e", gh, ghSteps("- run: |\n    set +e\n    gitleaks detect\n    echo done"), 1, model.High, 8},
		{"shell without -e", gh, ghSteps("- shell: bash {0}\n  run: |\n    bandit -r .\n    echo done"), 1, model.High, 0},
		{"gitlab set +e", gl, "scan:\n  script:\n    - set +e\n    - checkov -d .\n    - echo done\n", 1, model.High, 4},
		{"set +o errexit", gl, "scan:\n  script:\n    - set +o errexit\n    - trivy fs --exit-code 1 .\n    - echo done\n", 1, model.High, 0},
		{"before_script set +e", gl, "default:\n  before_script:\n    - set +e\nscan:\n  script:\n    - semgrep ci\n    - echo done\n", 1, model.High, 0},
		{"status checked", gh, ghSteps("- run: |\n    set +e\n    gitleaks detect\n    rc=$?\n    exit $rc"), 0, -1, 0},
		{"scanner last", gl, "scan:\n  script:\n    - set +e\n    - echo start\n    - gitleaks detect\n", 0, -1, 0},
		{"errexit restored", gh, ghSteps("- run: |\n    set +e\n    ./setup.sh\n    set -e\n    gitleaks detect\n    echo ok"), 0, -1, 0},
		{"non-scanner", gh, ghSteps("- run: |\n    set +e\n    make test\n    echo done"), 0, -1, 0},
	})
}

func TestGL003(t *testing.T) {
	runCases(t, "GL003", []ruleCase{
		{"default shell tee", gh, ghSteps("- run: trivy fs --exit-code 1 . | tee out.txt"), 1, model.Medium, 6},
		{"sh tee", gh, ghSteps("- shell: sh\n  run: gitleaks detect | tee leaks.txt"), 1, model.Medium, 0},
		{"workflow default sh", gh, "on: push\ndefaults:\n  run:\n    shell: sh\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: semgrep ci | cat\n", 1, model.Medium, 0},
		{"gitlab pipefail off", gl, "scan:\n  script:\n    - set +o pipefail\n    - bandit -r . | tee b.txt\n", 1, model.Medium, 0},
		{"shell bash", gh, ghSteps("- shell: bash\n  run: trivy fs --exit-code 1 . | tee out.txt"), 0, -1, 0},
		{"set -o pipefail", gh, ghSteps("- run: |\n    set -eo pipefail\n    trivy fs --exit-code 1 . | tee out.txt"), 0, -1, 0},
		{"gitlab default", gl, "scan:\n  script:\n    - trivy fs --exit-code 1 . | tee out.txt\n", 0, -1, 0},
		{"scanner last in pipe", gh, ghSteps("- run: cat files.txt | gitleaks detect --pipe"), 0, -1, 0},
		{"custom pipefail shell", gh, ghSteps("- shell: bash -eo pipefail {0}\n  run: semgrep ci | tee s.txt"), 0, -1, 0},
	})
}

func TestGL004(t *testing.T) {
	runCases(t, "GL004", []ruleCase{
		{"step true", gh, ghSteps("- run: semgrep ci\n  continue-on-error: true"), 1, model.High, 7},
		{"job true", gh, "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n    steps:\n      - uses: gitleaks/gitleaks-action@v2\n", 1, model.High, 5},
		{"expression", gh, ghSteps("- run: semgrep ci\n  continue-on-error: ${{ matrix.experimental }}"), 1, model.Medium, 0},
		{"expression true literal", gh, ghSteps("- run: semgrep ci\n  continue-on-error: ${{ true }}"), 1, model.High, 0},
		{"action step", gh, ghSteps("- uses: anchore/scan-action@v6\n  continue-on-error: true"), 1, model.High, 0},
		{"false", gh, ghSteps("- run: semgrep ci\n  continue-on-error: false"), 0, -1, 0},
		{"non-scanner", gh, ghSteps("- run: npm run lint\n  continue-on-error: true"), 0, -1, 0},
		{"codeql", gh, ghSteps("- uses: github/codeql-action/analyze@v3\n  continue-on-error: true"), 0, -1, 0},
		{"expression false", gh, ghSteps("- run: semgrep ci\n  continue-on-error: ${{ false }}"), 0, -1, 0},
	})
}

func TestGL005(t *testing.T) {
	runCases(t, "GL005", []ruleCase{
		{"allow_failure true", gl, "trivy:\n  script:\n    - trivy fs --exit-code 1 .\n  allow_failure: true\n", 1, model.High, 4},
		{"exit codes include 1", gl, "bandit:\n  script:\n    - bandit -r .\n  allow_failure:\n    exit_codes: [1, 2]\n", 1, model.High, 0},
		{"exit code from flag", gl, "trivy:\n  script:\n    - trivy fs --exit-code 5 .\n  allow_failure:\n    exit_codes: 5\n", 1, model.High, 0},
		{"grype code 2", gl, "grype:\n  script:\n    - grype dir:. --fail-on high\n  allow_failure:\n    exit_codes: [2]\n", 1, model.High, 0},
		{"after_script", gl, "scan:\n  script:\n    - make\n  after_script:\n    - gitleaks detect\n", 1, model.High, 5},
		{"inherited via extends", gl, ".allowed:\n  allow_failure: true\nscan:\n  extends: .allowed\n  script:\n    - semgrep ci\n", 1, model.High, 2},
		{"all rules", gl, "scan:\n  script:\n    - semgrep ci\n  rules:\n    - if: $A\n      allow_failure: true\n", 1, model.High, 0},
		{"some rules", gl, "scan:\n  script:\n    - semgrep ci\n  rules:\n    - if: $A\n      allow_failure: true\n    - if: $B\n", 1, model.Medium, 0},
		{"other exit codes", gl, "scan:\n  script:\n    - gitleaks detect\n  allow_failure:\n    exit_codes: [3]\n", 0, -1, 0},
		{"allow_failure false", gl, "scan:\n  script:\n    - gitleaks detect\n  allow_failure: false\n", 0, -1, 0},
		{"non-scanner job", gl, "test:\n  script:\n    - npm test\n  allow_failure: true\n", 0, -1, 0},
		{"grype code 1 is not its failure", gl, "grype:\n  script:\n    - grype dir:. --fail-on high\n  allow_failure:\n    exit_codes: [1]\n", 0, -1, 0},
	})
}

func TestGL006(t *testing.T) {
	runCases(t, "GL006", []ruleCase{
		{"bandit exit-zero", gh, ghSteps("- run: bandit -r src --exit-zero"), 1, model.High, 6},
		{"checkov soft-fail gitlab", gl, "iac:\n  script:\n    - checkov -d infra --soft-fail\n", 1, model.High, 3},
		{"gitleaks exit code 0", gh, ghSteps("- run: gitleaks detect --exit-code 0"), 1, model.High, 0},
		{"npm audit none", gl, "deps:\n  script:\n    - npm audit --audit-level none\n", 1, model.High, 0},
		{"trivy env", gl, "variables:\n  TRIVY_EXIT_CODE: \"0\"\nscan:\n  script:\n    - trivy fs .\n", 1, model.High, 0},
		{"inline env", gh, ghSteps("- run: TRIVY_EXIT_CODE=0 trivy fs ."), 1, model.High, 0},
		{"export env", gh, ghSteps("- run: |\n    export TRIVY_EXIT_CODE=0\n    trivy fs ."), 1, model.High, 0},
		{"variable flag", gl, "variables:\n  FLAGS: --exit-zero\nscan:\n  script:\n    - bandit -r . $FLAGS\n", 1, model.High, 0},
		{"docker env", gh, ghSteps("- run: docker run -e TRIVY_EXIT_CODE=0 aquasec/trivy fs ."), 1, model.High, 0},
		{"pipx run", gh, ghSteps("- run: pipx run bandit -r . --exit-zero"), 1, model.High, 0},
		{"poetry python -m", gh, ghSteps("- run: poetry run python -m bandit -r . --exit-zero"), 1, model.High, 0},
		{"echo mention", gh, ghSteps("- run: echo \"bandit --exit-zero is not allowed\""), 0, -1, 0},
		{"gating value", gh, ghSteps("- run: gitleaks detect --exit-code 1"), 0, -1, 0},
		{"soft-fail false", gl, "iac:\n  script:\n    - checkov -d . --soft-fail=false\n", 0, -1, 0},
		{"grep for flag", gh, ghSteps("- run: grep -- --exit-zero Makefile"), 0, -1, 0},
	})
}

func TestGL007(t *testing.T) {
	runCases(t, "GL007", []ruleCase{
		{"trivy no exit code", gh, ghSteps("- run: trivy image app:latest"), 1, model.Medium, 6},
		{"grype no fail-on", gl, "scan:\n  script:\n    - grype dir:.\n", 1, model.Medium, 3},
		{"semgrep scan no error", gh, ghSteps("- run: semgrep scan --config auto"), 1, model.Medium, 0},
		{"bare semgrep", gl, "scan:\n  script:\n    - semgrep --config p/ci .\n", 1, model.Medium, 0},
		{"trivy action no exit-code", gh, ghSteps("- uses: aquasecurity/trivy-action@0.28.0\n  with:\n    scan-type: fs"), 1, model.Medium, 6},
		{"trufflehog", gh, ghSteps("- run: trufflehog git file://."), 1, model.Medium, 0},
		{"snyk monitor info", gh, ghSteps("- run: snyk monitor"), 1, model.Info, 0},
		{"snyk action monitor", gh, ghSteps("- uses: snyk/actions/node@master\n  with:\n    command: monitor"), 1, model.Info, 0},
		{"trivy gating", gh, ghSteps("- run: trivy image --exit-code 1 app:latest"), 0, -1, 0},
		{"semgrep ci", gl, "scan:\n  script:\n    - semgrep ci\n", 0, -1, 0},
		{"unknown exit code", gh, ghSteps("- run: trivy fs --exit-code ${{ inputs.code }} ."), 0, -1, 0},
		{"config file", gh, ghSteps("- run: trivy fs --config trivy.yaml ."), 0, -1, 0},
		{"trivy env gating", gh, "on: push\nenv:\n  TRIVY_EXIT_CODE: 1\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: aquasecurity/trivy-action@0.28.0\n", 0, -1, 0},
		{"codeql", gh, ghSteps("- uses: github/codeql-action/analyze@v3"), 0, -1, 0},
		{"version check", gh, ghSteps("- run: trivy --version"), 0, -1, 0},
	})
}

func TestGL008(t *testing.T) {
	runCases(t, "GL008", []ruleCase{
		{"trivy exit-code 0", gh, ghSteps("- uses: aquasecurity/trivy-action@0.28.0\n  with:\n    exit-code: '0'"), 1, model.High, 8},
		{"scan-action fail-build", gh, ghSteps("- uses: anchore/scan-action@v6\n  with:\n    fail-build: false"), 1, model.High, 0},
		{"checkov soft_fail", gh, ghSteps("- uses: bridgecrewio/checkov-action@v12\n  with:\n    soft_fail: true"), 1, model.High, 0},
		{"pip-audit allow failure", gh, ghSteps("- uses: pypa/gh-action-pip-audit@v1.1.0\n  with:\n    internal-be-careful-allow-failure: true"), 1, model.High, 0},
		{"gosec args", gh, ghSteps("- uses: securego/gosec@v2\n  with:\n    args: '-no-fail ./...'"), 1, model.High, 8},
		{"trivy env 0", gh, ghSteps("- uses: aquasecurity/trivy-action@0.28.0\n  env:\n    TRIVY_EXIT_CODE: '0'"), 1, model.High, 0},
		{"scan-action default", gh, ghSteps("- uses: anchore/scan-action@v6\n  with:\n    image: app"), 0, -1, 0},
		{"checkov soft_fail false", gh, ghSteps("- uses: bridgecrewio/checkov-action@v12\n  with:\n    soft_fail: false"), 0, -1, 0},
		{"expression input", gh, ghSteps("- uses: anchore/scan-action@v6\n  with:\n    fail-build: ${{ inputs.fail }}"), 0, -1, 0},
		{"unknown action", gh, ghSteps("- uses: example/scan-action@v1\n  with:\n    soft_fail: true"), 0, -1, 0},
	})
}

func TestGL009(t *testing.T) {
	runCases(t, "GL009", []ruleCase{
		{"step if false", gh, ghSteps("- if: false\n  run: semgrep ci"), 1, model.High, 6},
		{"step if expr false", gh, ghSteps("- if: ${{ false }}\n  uses: gitleaks/gitleaks-action@v2"), 1, model.High, 0},
		{"job if false", gh, "on: push\njobs:\n  scan:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: semgrep ci\n", 1, model.High, 4},
		{"when never", gl, "scan:\n  script:\n    - semgrep ci\n  when: never\n", 1, model.High, 4},
		{"when manual", gl, "scan:\n  script:\n    - semgrep ci\n  when: manual\n", 1, model.High, 0},
		{"rules never", gl, "scan:\n  script:\n    - semgrep ci\n  rules:\n    - when: never\n", 1, model.High, 0},
		{"rules manual", gl, "scan:\n  script:\n    - semgrep ci\n  rules:\n    - if: $X\n      when: never\n    - when: manual\n", 1, model.High, 0},
		{"template disabled", gl, "include:\n  - template: Jobs/SAST.gitlab-ci.yml\nvariables:\n  SAST_DISABLED: 'true'\n", 1, model.High, 4},
		{"conditional if", gh, ghSteps("- if: github.event_name == 'push'\n  run: semgrep ci"), 0, -1, 0},
		{"rules with a runnable rule", gl, "scan:\n  script:\n    - semgrep ci\n  rules:\n    - if: $X\n      when: never\n    - when: on_success\n", 0, -1, 0},
		{"template enabled", gl, "include:\n  - template: Jobs/SAST.gitlab-ci.yml\nvariables:\n  SAST_DISABLED: 'false'\n", 0, -1, 0},
		{"disable var without template", gl, "variables:\n  SAST_DISABLED: 'true'\nscan:\n  script:\n    - semgrep ci\n", 0, -1, 0},
		{"non-scanner manual", gl, "deploy:\n  script:\n    - ./deploy.sh\n  when: manual\n", 0, -1, 0},
	})
}

func TestGL010(t *testing.T) {
	runCases(t, "GL010", []ruleCase{
		{"no reason", gh, ghSteps("- run: semgrep ci # gatelint:ignore GL004"), 1, model.Low, 6},
		{"short reason", gl, "scan:\n  script:\n    - semgrep ci || true # gatelint:ignore GL001 todo\n", 1, model.Low, 0},
		{"unknown rule", gh, ghSteps("- run: semgrep ci # gatelint:ignore GL123 a perfectly fine reason"), 1, model.Low, 0},
		{"no ids", gh, ghSteps("- run: semgrep ci # gatelint:ignore because I said so"), 1, model.Low, 0},
		{"valid", gh, ghSteps("- run: semgrep ci || true # gatelint:ignore GL001 tracked in SEC-42 until Friday"), 0, -1, 0},
		{"no directives", gl, "scan:\n  script:\n    - semgrep ci\n", 0, -1, 0},
	})
}

func TestSuppressionAppliesAndInvalidDoesNot(t *testing.T) {
	src := ghSteps(`- run: trivy fs --exit-code 1 . || true # gatelint:ignore GL001 base image fix tracked in SEC-7
- run: gitleaks detect || true # gatelint:ignore GL001
- name: nightly
  # gatelint:ignore GL004,GL001 nightly report only, PR gate in ci.yml
  continue-on-error: true
  run: semgrep ci || true`)
	fs, _ := analyze(t, gh, src)
	var suppressed, gl001Open, gl010 int
	for _, f := range fs {
		switch {
		case f.Suppressed:
			suppressed++
			if f.SuppressionReason == "" {
				t.Errorf("suppressed finding without reason: %+v", f)
			}
		case f.RuleID == "GL001":
			gl001Open++
		case f.RuleID == "GL010":
			gl010++
		}
	}
	if suppressed != 2 || gl001Open != 2 || gl010 != 1 {
		t.Fatalf("suppressed=%d open GL001=%d GL010=%d, want 2, 2, 1: %+v", suppressed, gl001Open, gl010, fs)
	}
}

func TestDisabledScannerOnlyReportsGL009(t *testing.T) {
	fs, _ := analyze(t, gh, ghSteps("- if: false\n  continue-on-error: true\n  run: trivy fs . || true"))
	if len(fs) != 1 || fs[0].RuleID != "GL009" {
		t.Fatalf("want only GL009, got %+v", fs)
	}
}

func TestMitigation(t *testing.T) {
	cases := []struct {
		name     string
		platform string
		src      string
		rule     string
		want     model.Severity
		note     string
	}{
		{"gating twin", gh, ghSteps(`- uses: aquasecurity/trivy-action@0.28.0
  with:
    format: sarif
    output: trivy.sarif
    exit-code: '0'
- uses: aquasecurity/trivy-action@0.28.0
  with:
    exit-code: '1'`), "GL008", model.Low, "gating mode"},
		{"sarif upload", gh, ghSteps(`- run: semgrep scan --sarif -o semgrep.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: semgrep.sarif`), "GL007", model.Low, "code scanning"},
		{"later gate step", gh, ghSteps(`- run: gitleaks detect --exit-code 0 --report-path leaks.json
- run: |
    n=$(jq length leaks.json)
    if [ "$n" -gt 0 ]; then exit 1; fi`), "GL006", model.Low, "later command"},
		{"gitlab later job", gl, `report:
  script:
    - bandit -r . -f json -o bandit.json --exit-zero
gate:
  script:
    - jq -e '.results | length == 0' bandit.json
`, "GL006", model.Low, "later command"},
		{"redirect then gate", gh, ghSteps(`- run: |
    checkov -s -d fixture > report.txt
    grep CKV_AWS_20 report.txt
    exit $?`), "GL006", model.Low, "later command"},
		{"gitlab security report", gl, `sast:
  script:
    - semgrep ci --json > gl-sast-report.json || true
  artifacts:
    reports:
      sast: gl-sast-report.json
`, "GL001", model.Medium, "GitLab report artifact"},
		{"gitlab plain artifact", gl, `sast:
  script:
    - semgrep ci --json > semgrep.json || true
  artifacts:
    paths: [semgrep.json]
`, "GL001", model.High, ""},
		{"no mitigation without report", gh, ghSteps(`- uses: anchore/scan-action@v6
  with:
    fail-build: false
- uses: anchore/scan-action@v6`), "GL008", model.High, ""},
		{"unrelated later step", gh, ghSteps(`- run: gitleaks detect --exit-code 0 --report-path leaks.json
- run: exit 1`), "GL006", model.High, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, _ := analyze(t, c.platform, c.src)
			for _, f := range fs {
				if f.RuleID != c.rule {
					continue
				}
				if f.Severity != c.want {
					t.Errorf("severity = %v, want %v (%+v)", f.Severity, c.want, f)
				}
				if c.note != "" && (len(f.Notes) == 0 || !strings.Contains(f.Notes[0], c.note)) {
					t.Errorf("notes = %v, want one containing %q", f.Notes, c.note)
				}
				return
			}
			t.Fatalf("no %s finding: %+v", c.rule, fs)
		})
	}
}

func TestCoverageStatuses(t *testing.T) {
	src := ghSteps(`- run: trivy fs --exit-code 1 .
- run: trivy fs .
- run: trivy fs --exit-code 1 . || true
- if: false
  run: semgrep ci
- run: trivy fs --exit-code $CODE .
- uses: github/codeql-action/analyze@v3`)
	fs, ctx := analyze(t, gh, src)
	cov := rules.Coverage(ctx, fs, []string{"ci.yml"})
	if len(cov) != 1 {
		t.Fatalf("coverage files = %d", len(cov))
	}
	var got []model.GateStatus
	for _, e := range cov[0].Scanners {
		got = append(got, e.Status)
	}
	want := []model.GateStatus{model.StatusGating, model.StatusNonGating, model.StatusNeutered, model.StatusDisabled, model.StatusUnknown, model.StatusNonGating}
	if len(got) != len(want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d status = %s, want %s", i, got[i], want[i])
		}
	}
	if cov[0].Scanners[2].Rules[0] != "GL001" {
		t.Errorf("neutered entry rules = %v", cov[0].Scanners[2].Rules)
	}
	if cov[0].Scanners[4].Note == "" {
		t.Error("unknown entry has no note")
	}
}

func TestCoverageTemplatesAndConfig(t *testing.T) {
	fs, ctx := analyze(t, gl, "include:\n  - template: Jobs/Secret-Detection.gitlab-ci.yml\nscan:\n  script:\n    - trivy fs --config trivy.yaml .\n")
	cov := rules.Coverage(ctx, fs, nil)
	if len(cov) != 1 || len(cov[0].Scanners) != 2 {
		t.Fatalf("coverage = %+v", cov)
	}
	for _, e := range cov[0].Scanners {
		switch e.Scanner {
		case "Trivy":
			if e.Status != model.StatusUnknown || !strings.Contains(e.Note, "trivy.yaml") {
				t.Errorf("trivy entry = %+v", e)
			}
		case "GitLab Secret Detection":
			if e.Status != model.StatusNonGating || e.Note == "" {
				t.Errorf("template entry = %+v", e)
			}
		default:
			t.Errorf("unexpected entry %+v", e)
		}
	}
}

func TestDisabledRules(t *testing.T) {
	p, err := github.Parse("ci.yml", []byte(ghSteps("- run: trivy fs . || true")))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &rules.Context{Catalog: catalog.Default(), Pipelines: []*model.Pipeline{p}, Disabled: map[string]bool{"GL001": true, "GL007": true}}
	rules.Collect(ctx, nil)
	if fs := rules.Run(ctx); len(fs) != 0 {
		t.Fatalf("disabled rules still reported: %+v", fs)
	}
}

func TestRepoConfigFileMakesGatingUnknown(t *testing.T) {
	p, err := github.Parse("ci.yml", []byte(ghSteps("- run: grype dir:.")))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &rules.Context{Catalog: catalog.Default(), Pipelines: []*model.Pipeline{p}}
	rules.Collect(ctx, func(_ *model.Pipeline, name string) bool { return name == ".grype.yaml" })
	for _, f := range rules.Run(ctx) {
		if f.RuleID == "GL007" {
			t.Fatalf("GL007 reported although .grype.yaml exists: %+v", f)
		}
	}
}

func TestFingerprintsStableAcrossLineShifts(t *testing.T) {
	a, _ := analyze(t, gh, ghSteps("- run: trivy fs . || true"))
	b, _ := analyze(t, gh, ghSteps("- run: echo hi\n- run: trivy fs . || true"))
	fp := func(fs []model.Finding, rule string) string {
		for _, f := range fs {
			if f.RuleID == rule {
				return f.Fingerprint
			}
		}
		return ""
	}
	if fp(a, "GL001") == "" || fp(a, "GL001") == fp(b, "GL001") && a[0].Step != b[0].Step {
		t.Fatalf("fingerprints: %q vs %q", fp(a, "GL001"), fp(b, "GL001"))
	}
}

func TestRegistry(t *testing.T) {
	all := rules.All()
	if len(all) != 10 {
		t.Fatalf("rules = %d, want 10", len(all))
	}
	for i, r := range all {
		want := "GL0" + string(rune('0'+(i+1)/10)) + string(rune('0'+(i+1)%10))
		if r.ID != want {
			t.Errorf("rule %d id = %s, want %s", i, r.ID, want)
		}
		if r.Title == "" || r.Explanation == "" || r.Hint == "" || r.Before == "" || r.After == "" || r.Platforms == "" {
			t.Errorf("%s is missing documentation fields", r.ID)
		}
		if !strings.HasSuffix(r.HelpURI(), r.ID+".md") {
			t.Errorf("%s help URI = %s", r.ID, r.HelpURI())
		}
		if rules.ByID(strings.ToLower(r.ID)) != r {
			t.Errorf("ByID(%s) failed", r.ID)
		}
	}
	if rules.ByID("GL999") != nil {
		t.Error("ByID(GL999) should be nil")
	}
}
