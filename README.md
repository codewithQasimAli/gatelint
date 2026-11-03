# gatelint

Find the security scanners in your CI that can never fail a build.

[Rules](#rules) · [Install](#install) · [GitHub Action](#github-action) · [GitLab CI](#gitlab-ci) · [Suppressions](#suppressions)

## The problem

CI pipelines run security scanners such as Trivy, Semgrep, Gitleaks, Bandit and Checkov, but to keep a build green someone adds `|| true`, `continue-on-error: true`, `allow_failure: true`, `--exit-zero`, `--soft-fail`, `exit-code: 0`, or disables the job. The scanner still runs and still prints findings, so everyone believes the gate protects them, but it can never fail a build.

```yaml
# Before: both scans run, neither can fail the build
- run: trivy image --exit-code 1 myapp:latest || true
- uses: anchore/scan-action@v6
  with: { image: myapp:latest, fail-build: false }
# After: a finding fails the job
- run: trivy image --exit-code 1 myapp:latest
- uses: anchore/scan-action@v6
  with: { image: myapp:latest }
```

gatelint reads GitHub Actions workflows, composite actions and GitLab CI configuration, finds every scanner invocation, and reports the ones that cannot gate, with the exact file, line, the reason, and the fix. It knows each scanner's flags and actions (for example, that Trivy exits 0 unless `--exit-code` is set, that `semgrep ci` gates while `semgrep scan` does not, and that Grype fails with exit code 2), and it parses shell scripts into a syntax tree instead of matching text, so `echo "trivy failed" || true` is not a finding but `trivy fs . && echo ok` in the middle of a script is.

## Install

```bash
go install github.com/codewithQasimAli/gatelint/cmd/gatelint@latest
```

Tagged releases are built by GoReleaser and publish archives for Linux, macOS and Windows on amd64 and arm64, with a `checksums.txt` file, on the [releases page](https://github.com/codewithQasimAli/gatelint/releases).

To build and run the container image locally:

```bash
docker build -t gatelint .
```

```bash
docker run --rm -v "$PWD:/work:ro" gatelint scan .
```

## Quick start

Run it at the root of a repository:

```bash
gatelint scan
```

It finds `.github/workflows/*.yml`, `action.yml` files and `.gitlab-ci.yml` (plus its local includes) on its own, prints the findings and a gate coverage summary, and exits 1 if there are high-severity findings. To see every rule:

```bash
gatelint rules
```

## Example

This is the output of a real run on [`testdata/example/.github/workflows/security.yml`](testdata/example/.github/workflows/security.yml); a test keeps this block in sync with the binary.

```text
$ gatelint scan testdata/example
SEVERITY  RULE   LOCATION                                            JOB / STEP               MESSAGE
HIGH      GL001  testdata/example/.github/workflows/security.yml:11  scan / Dependency audit  npm audit failure is swallowed by `|| true`
          fix: remove the "|| true" (or equivalent) so a failing scan fails the job
MEDIUM    GL007  testdata/example/.github/workflows/security.yml:14  scan / Container scan    aquasecurity/trivy-action@0.28.0 exits 0 when it finds issues and no gating option is set
          fix: set exit-code: '1' on the step so findings fail the build
HIGH      GL004  testdata/example/.github/workflows/security.yml:20  scan / SAST              Semgrep runs in a step with continue-on-error: true, so a failing scan does not fail the workflow
          fix: remove continue-on-error, or move non-blocking experiments to a separate job

Gate coverage
  testdata/example/.github/workflows/security.yml
    npm audit  scan / Dependency audit  line 11    neutered (GL001)
    Trivy      scan / Container scan    line 14    non-gating (GL007)
      trivy-action exits 0 on findings unless exit-code is set to a non-zero value
    Semgrep    scan / SAST              line 19    neutered (GL004)
    Gitleaks   scan / Secrets           line 23    gating

Summary: 3 findings (2 high, 1 medium, 0 low, 0 info), 0 suppressed; 4 scanners in 1 file: 1 gating, 2 neutered, 1 non-gating
```

## GitHub Action

```yaml
name: gatelint
on: [push, pull_request]
permissions:
  contents: read
jobs:
  gatelint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: codewithQasimAli/gatelint@v0.1.0
        with:
          fail-on: high          # high, medium, low or none
          format: sarif          # sarif, json, codequality or table
          sarif-file: gatelint.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gatelint.sarif
```

Inputs: `path` (default `.`), `fail-on` (default `high`), `format` (default `sarif`), `sarif-file` (default `gatelint.sarif`), `version` (default `latest`). The action installs gatelint with `go install`, writes the report, then runs a second time to fail the step according to `fail-on`. Pin the action to a commit SHA in your own workflows.

## GitLab CI

Include the template and the findings appear in the merge request's Code Quality widget:

```yaml
include:
  - remote: https://raw.githubusercontent.com/codewithQasimAli/gatelint/main/templates/gatelint.gitlab-ci.yml

gatelint:
  variables:
    GATELINT_FAIL_ON: high
```

The job publishes `gl-code-quality-report.json` as `artifacts:reports:codequality`. Variables: `GATELINT_VERSION`, `GATELINT_PATH`, `GATELINT_FAIL_ON`, `GATELINT_REPORT`.

## Rules

| ID | Severity | Platforms | Title |
| --- | --- | --- | --- |
| [GL001](docs/rules/GL001.md) | HIGH | GitHub, GitLab | Scanner failure swallowed by the shell (`\|\| true`, `\|\| echo`, `!`, `&&` mid-script, `$(...)`, `&`) |
| [GL002](docs/rules/GL002.md) | HIGH | GitHub, GitLab | errexit disabled before a scanner (`set +e`, shell without `-e`) |
| [GL003](docs/rules/GL003.md) | MEDIUM | GitHub, GitLab | Scanner piped without pipefail |
| [GL004](docs/rules/GL004.md) | HIGH | GitHub | `continue-on-error` on a scanner step or job (MEDIUM when it is an expression) |
| [GL005](docs/rules/GL005.md) | HIGH | GitLab | Scanner job allowed to fail (`allow_failure`, matching `exit_codes`, `after_script`) |
| [GL006](docs/rules/GL006.md) | HIGH | GitHub, GitLab | Neutering flag on the scanner command line (`--exit-zero`, `--soft-fail`, `--exit-code 0`, ...) |
| [GL007](docs/rules/GL007.md) | MEDIUM | GitHub, GitLab | Scanner does not gate by default and no gating option is set |
| [GL008](docs/rules/GL008.md) | HIGH | GitHub | Neutering input on a scanner action (`exit-code: '0'`, `fail-build: false`, `soft_fail: true`, ...) |
| [GL009](docs/rules/GL009.md) | HIGH | GitHub, GitLab | Scanner disabled (`if: false`, `when: never`, `when: manual`, `*_DISABLED` variables) |
| [GL010](docs/rules/GL010.md) | LOW | GitHub, GitLab | Suppression without a reason |

Scanners in the built-in catalog: Bandit, Trivy, Grype, Semgrep, Gitleaks, Checkov, tfsec, npm/pnpm/yarn audit, pip-audit, Snyk, CodeQL, gosec, TruffleHog, gatelint itself, and the GitLab SAST, IaC, Secret Detection, Dependency Scanning, Container Scanning and DAST templates. They are recognised when run directly, through `python -m`, `pipx run`, `uvx`, `poetry run`, `npx` and similar runners, through `docker run <image>`, through wrappers such as `sudo`, `env` and `timeout`, and through their GitHub Actions. Add your own scanners in `.gatelint.yml` (see [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-scanner)).

When a neutered scanner only produces a report while something else gates (the same scanner also runs in gating mode, a later command fails on the report file, or the report is uploaded to code scanning or published as a GitLab security report), gatelint lowers the severity and says why.

## Gate coverage

Below the findings, gatelint lists every scanner it found in each file with one of these statuses:

| Status | Meaning |
| --- | --- |
| `gating` | A finding fails the build. |
| `neutered` | The scanner would gate, but the listed rules show why it cannot. |
| `non-gating` | The scanner does not fail builds by default (Trivy without `--exit-code`, `snyk monitor`, CodeQL, GitLab security templates). |
| `disabled` | The scanner never runs automatically. |
| `unknown` | Gating depends on something gatelint cannot see: a config file, an expression or an unresolved variable. |

The summary is also included in the JSON report under `coverage`, so you can track how many of your scanners actually gate.

## Suppressions

Suppress a finding on the same line, or on the line directly above, with the rule IDs and a reason of at least 10 characters:

```yaml
      - name: Nightly report
        # gatelint:ignore GL004 nightly dashboard only; the PR gate is in ci.yml
        continue-on-error: true
        run: semgrep ci
```

Separate several IDs with commas (`GL001,GL003`). A suppression without a reason does not suppress anything and is reported as GL010. Suppressed findings stay in JSON and SARIF output, marked as suppressed with the reason, so they remain auditable; the table and Code Quality reports leave them out.

## Configuration

An optional `.gatelint.yml` in the scanned directory (or `--config FILE`):

```yaml
fail-on: medium              # default for --fail-on
disable-rules: [GL003]
exclude: [legacy/**]
scanners:                    # add or override catalog entries
  - id: inhouse-scanner
    name: In-house scanner
    commands: [inhouse-scan]
    modes:
      - gates-by-default: true
    settings:
      - names: [--report-only]
        neuter-when: set
        description: never exits non-zero
```

## Command line

```text
gatelint scan [paths...]     scan files and directories (default ".")
  --format table|json|sarif|codequality   (default table)
  --output FILE                write the report to a file
  --fail-on high|medium|low|none          (default high)
  --platform auto|github|gitlab           (default auto)
  --config FILE                configuration file
  --no-color                   disable colours (NO_COLOR is honoured too)
  --quiet                      table format: findings only
gatelint rules [ID]          list rules, or describe one
gatelint version             print version, commit and build date
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No unsuppressed findings at or above `--fail-on`. |
| 1 | At least one unsuppressed finding at or above `--fail-on`. |
| 2 | Usage error, unreadable path, or a YAML file that could not be parsed. |

## How it compares

| Capability | General CI security linters | gatelint |
| --- | --- | --- |
| Knows which flags and inputs neuter each scanner, and which scanners do not gate by default | Rarely; usually a short list of patterns | Per-tool catalog with modes, environment variables and action inputs, extendable in config |
| Detects `\|\| true` and similar | Text patterns, often on any command | Shell syntax tree; only when the swallowed command is a scanner |
| Shell semantics: errexit, `&&` lists, pipefail defaults, `$(...)`, `bash -c` | No | Yes, including GitHub's per-shell defaults |
| GitHub Actions and GitLab CI | Usually one platform | Both, including composite actions, reusable workflows, includes, `extends:` and `!reference` |
| Gate coverage summary per file | No | Yes |
| Report-only scans next to a real gate | Reported at full severity | Recognised and lowered, with an explanation |
| Suppressions | Often allowed without explanation | Reason required, kept visible in JSON and SARIF |

General-purpose CI linters cover many more topics (permissions, injection, pinning); gatelint does one thing in depth and works well alongside them.

## Roadmap

- Resolve GitHub `matrix:` values to evaluate conditional `continue-on-error`.
- Read scanner configuration files (`trivy.yaml`, `.grype.yaml`, `.checkov.yaml`) instead of reporting `unknown`.
- More scanners in the catalog (govulncheck, osv-scanner, zizmor, dependency-review-action, Brakeman, bundler-audit, cargo audit).
- Azure Pipelines, Bitbucket Pipelines and CircleCI.
- Follow remote GitLab includes and reusable workflows when given a token.

## License

Apache License 2.0. See [LICENSE](LICENSE).
