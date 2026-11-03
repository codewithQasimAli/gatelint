# Design decisions

Each entry records a decision, the alternatives considered, and the reason.

## Toolchain and dependencies

**Go 1.24, mvdan.cc/sh v3.12.0.** The installed toolchain is Go 1.24.7 and the bundled golangci-lint (v2.5.0) is built with Go 1.25, so it cannot lint a module that declares Go 1.26. mvdan.cc/sh v3.13+ requires Go 1.25 and v3.14 requires Go 1.26. *Alternatives:* let `GOTOOLCHAIN=auto` download Go 1.26 and use the newest sh release. *Reason:* staying on 1.24 keeps the module buildable with the installed toolchain and lintable with the installed linter; v3.12 has every parser feature gatelint uses.

**Dependencies are limited to yaml.v3, mvdan.cc/sh and cobra.** SARIF and Code Quality structures are hand-written. *Alternative:* a SARIF library. *Reason:* the subset gatelint emits is small and stable, and fewer dependencies is better for a security tool.

## Scanner catalog

The catalog lives in `internal/catalog/default.yml` and is embedded. Defaults were checked against upstream sources:

| Scanner | Default | Source checked |
| --- | --- | --- |
| Trivy | exits 0 on findings; `--exit-code N` (or `TRIVY_EXIT_CODE`) gates | `pkg/flag/report_flags.go` (no default for `exit-code`); trivy-action `action.yaml` has no default for `exit-code` and maps it to `TRIVY_EXIT_CODE` |
| Grype | exits 0; `--fail-on`/`-f` exits **2** | `cmd/grype/cli/options/grype.go`: "set the return code to 2 if a vulnerability is found" |
| anchore/scan-action | `fail-build` defaults to `"true"` | `action.yml` |
| Semgrep | `semgrep scan` exits 0 unless `--error`; `semgrep ci` fails on blocking findings | `cli/src/semgrep/commands/scan.py` (`--error/--no-error`, default off) |
| Gitleaks | exits 1 on leaks; `--exit-code` changes it | `cmd/root.go`: `Int("exit-code", 1, ...)` |
| gitleaks-action | gates | runs the CLI with its default exit code |
| Checkov | fails on failed checks; `--soft-fail`/`-s` exits 0 | README; checkov-action passes `soft_fail` through |
| tfsec | fails; `--soft-fail`/`-s` suppresses the error code | `cmd/tfsec/cmd/flags.go` |
| Bandit | exits 1; `--exit-zero` exits 0 | `bandit/cli/main.py` |
| PyCQA/bandit-action | never fails: runs `bandit ... \|\| true` and uploads SARIF | `action.yml`; treated like CodeQL (coverage note only) |
| npm audit | exits non-zero on vulnerabilities; `--audit-level=none` never does | npm `definitions.js` (`audit-level` accepts `none`) and `npm-audit.md` |
| pip-audit | exits 1 on vulnerabilities; "cannot be suppressed" by a flag | README "Exit codes" |
| pypa/gh-action-pip-audit | gates; `internal-be-careful-allow-failure: true` keeps it green | `action.yml` |
| Snyk | `snyk test` exits 1 on issues; `snyk monitor` exits 0, 2 or 3 and never on vulnerabilities | `help/cli-commands/monitor.md` |
| snyk/actions/* | `command` defaults to `test` | `node/action.yml` |
| gosec | exits 1 on issues; `-no-fail` exits 0 | `cmd/gosec/main.go` |
| securego/gosec action | passes `args` to gosec | `action.yml` |
| TruffleHog | exits 0 unless `--fail` (then 183) | `main.go` |
| trufflehog action | passes `--fail` | `action.yml` |
| CodeQL | does not fail builds on alerts | codeql-action `analyze/action.yml`; coverage note only |

Uncertain entries: the semgrep-action (deprecated) is assumed to gate because it ran `semgrep ci`; tfsec-sarif-action is assumed non-gating because it produces a SARIF report for upload. Checkov's `-s` short form is taken from its CLI help. GitLab template job names and `*_DISABLED` variables follow GitLab's documentation; templates are treated as non-gating because their jobs do not fail on findings and results are enforced through merge request approval policies.

**gatelint is in its own catalog.** `gatelint scan --fail-on none` neuters it just like `--exit-zero` neuters Bandit. *Reason:* it is a gate, and dogfooding the suppression syntax in `action.yml` and the GitLab template shows how a report-only run should be annotated.

## Rules

**A missing `exit-code` on trivy-action is GL007, not GL008.** The brief lists "exit-code '0' or missing" under GL008. *Alternative:* report both cases as GL008 (HIGH). *Reason:* GL008 is about inputs that actively neuter; an omitted input means the action uses its non-gating default, which is exactly GL007's definition (MEDIUM). Explicit `exit-code: '0'` remains GL008.

**`snyk monitor` is GL007 at INFO severity.** It never gates by design; INFO never fails a build with any `--fail-on` value.

**`&&` in the middle of a script is GL001.** Bash exempts the left side of `&&` from errexit, so `trivy fs . && echo ok` followed by more commands never fails the step. This was confirmed with `bash -ec 'false && true; echo still-running'`. As the last command it does gate, and is not reported.

**Swallowing through command substitution, `&`, negation and if conditions is GL001.** These all discard the scanner's status. An if condition is only reported when no branch contains a failing `exit`, `return` or `false`.

**`rc=$?` handling.** `scanner || rc=$?` is a swallow only when `rc` is not referenced later. Under `set +e`, GL002 is not reported when the next statement reads `$?` or when the scanner is the last statement (its status becomes the script's).

**GL003 on GitLab.** GitLab Runner starts job scripts with `case "$(set -o)" in *"pipefail"*) set -o pipefail;; esac; set -o errexit` (checked in `shells/bash.go`), so GL003 only fires on GitLab after an explicit `set +o pipefail`. GitHub's defaults were checked in the GitHub docs: an omitted shell runs `bash -e {0}` (no pipefail), `shell: bash` runs `bash --noprofile --norc -eo pipefail {0}`, `shell: sh` runs `sh -e {0}`.

**GitLab script lines run as one script.** `before_script` and `script` are analysed together (a `set +e` in `before_script` affects `script`); `after_script` is analysed separately and scanners there are GL005, because GitLab ignores its exit status.

**`when: manual` is GL009.** A manual job only runs when started by hand and is allowed to fail by default. Rules where every entry is `never` or `manual` are treated the same.

**Disabled scanners only report GL009.** Other rules stay quiet for a scanner that never runs, to avoid noise.

**Report-only mitigation.** A neutering finding is lowered to LOW when the same scanner gates elsewhere (same job on GitHub, same pipeline on GitLab) and the neutered run writes a report, or when a later command reads the report file and exits non-zero; it is lowered one level when the report is uploaded with `github/codeql-action/upload-sarif` or published as a GitLab `artifacts:reports` security report. *Alternative:* suppress such findings entirely. *Reason:* a report-only run is often legitimate, but whether the real gate exists is worth a second look, so the finding stays visible with a note. Report files are taken from output flags, action inputs, shell redirects and `tee` arguments.

**Expressions.** `${{ ... }}` (and GitLab `$[[ ... ]]`) are replaced with same-length placeholders before shell parsing so columns stay exact. `${{ env.NAME }}` is resolved when the value is known; other expressions make the value unknown, which yields status `unknown` instead of a finding. `continue-on-error` expressions are MEDIUM "conditional" findings.

**Non-POSIX shells.** pwsh, powershell, cmd and custom non-POSIX shells are analysed with the line-based fallback, and their findings carry medium confidence. Scripts the shell parser rejects use the same fallback.

## Suppressions

**A suppression without a valid reason does not suppress.** *Alternative:* suppress anyway and report GL010. *Reason:* otherwise a bare comment turns a HIGH finding into a LOW one, which would itself be a way to neuter the gate. GL010 findings cannot be suppressed.

**"Line directly above" applies only to comment-only lines.** A trailing comment on line N applies to line N only.

**Suppressed findings** appear in JSON and SARIF (`suppressions[].kind = inSource`), are counted in the table summary, and are omitted from the table rows and from Code Quality output, which has no suppression concept.

## Parsing

**`!reference` tags are resolved when the target exists locally.** The brief says to treat them as unresolved; section 9 says to resolve what is possible. Resolving local references finds scanners hidden behind them, and unresolved ones produce a "partial result" note and never fail parsing.

**`extends:` and includes deep-merge mappings and replace everything else,** matching GitLab's documented behaviour. Cycles and unknown parents produce notes. Values keep their original file and line through merges, so findings in included files point at the included file.

**Remote GitLab includes, project includes and remote reusable workflows are out of scope** and produce notes. Local includes (including `*` and `**` globs), local reusable workflows and local composite actions are followed.

**Local includes and references stay inside the repository.** A GitLab `include: local:` or a GitHub `uses: ./...` path that resolves outside the repository root (for example `../secret.yml`) is not read; a note is emitted instead. *Reason:* gatelint is often run on untrusted pull requests, and GitLab itself only includes files from the repository.

**YAML errors.** CRLF line endings and a UTF-8 BOM are normalised. A file that fails to parse is reported on stderr with its path and line (with a hint when tabs are used for indentation), the other files are still scanned, and the exit code is 2.

## Discovery and output

**Nested `testdata`, `vendor`, `node_modules`, `.git`, `.venv` and `venv` directories are skipped** when walking a directory (but not when they are the path given). This keeps `gatelint scan .` on this repository clean while `gatelint scan testdata/github` still works.

**Every `action.yml`/`action.yaml` is considered,** but only composite actions have steps to check.

**Paths in reports are relative to the working directory** when the file is below it, so SARIF uploads from the repository root line up with GitHub's file view.

**`--quiet` prints only the findings table;** errors still go to stderr.

**Fingerprints** hash rule, file, job, step, scanner and an occurrence counter, not line numbers, so they survive unrelated edits.

## Distribution

**The composite action runs gatelint twice:** once to write the report with `--fail-on none` (suppressed GL006 with a reason) and once to decide the exit status. This keeps the report even when the gate fails. Inputs are passed through environment variables, never interpolated into the script.

**The Dockerfile uses a plain `golang:1.24` builder with `go mod download`.** In this build environment Docker Hub returned `429 Too Many Requests` and the build container could not reach the module proxy, so the image was verified from a throwaway copy that used a registry mirror for the builder image and vendored modules. That workaround is specific to the sandbox and is not part of the repository. The resulting image ran `gatelint version` and exited 1 on `testdata/gitlab` as expected, as user `nonroot`.

**GoReleaser** was checked with `goreleaser check` and a local `goreleaser build --snapshot --single-target`; no release was published.

**golangci-lint** v2.5.0 (installed in the environment) runs with the `standard` linters plus `misspell`, `unconvert` and `bodyclose`; CI pins the same version.
