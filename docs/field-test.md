# Field test

gatelint was run against the CI configuration of 30 well-known public open-source repositories that use security scanners. This page reports aggregate results only. No repository is named or linked: a neutered gate in a public project is a security weakness, and reporting it is the maintainers' business, not this document's.

## Method

- Each repository was cloned with `git clone --depth 1 --filter=blob:none --sparse` and a sparse checkout of `.github/`, `.gitlab/`, `.gitlab-ci.yml` and `action.yml` only.
- `gatelint scan <clone> --format json --fail-on none` was run on each clone, using the build from this branch.
- Every finding and every scanner in the coverage summary was reviewed by hand against the source.
- The clones were deleted afterwards. They were kept outside the repository and never committed.

## Results

| Metric | Value |
| --- | --- |
| Repositories | 30 |
| CI files scanned | 927 (848 GitHub Actions, 79 GitLab CI including local includes) |
| Crashes | 0 |
| YAML parse errors | 0 |
| Repositories with at least one scanner | 22 |
| Scanner invocations found | 46 |
| Repositories with findings | 6 |

Scanners found:

| Scanner | Invocations |
| --- | --- |
| CodeQL | 19 |
| Semgrep | 7 |
| Trivy | 6 |
| Checkov | 4 |
| GitLab SAST template | 3 |
| TruffleHog | 3 |
| Gitleaks | 2 |
| GitLab Dependency Scanning template | 1 |
| GitLab Secret Detection template | 1 |

Gate coverage:

| Status | Invocations |
| --- | --- |
| gating | 9 |
| neutered | 7 |
| non-gating (by default or by design, including CodeQL and GitLab templates) | 30 |
| disabled | 0 |
| unknown | 0 |

Findings by rule:

| Rule | Findings |
| --- | --- |
| GL001 Scanner failure swallowed by the shell | 3 |
| GL004 continue-on-error on a scanner step or job | 2 |
| GL006 Neutering flag on the scanner command line | 3 |
| GL007 Scanner does not gate by default | 7 |
| GL008 Neutering input on a scanner action | 1 |
| Other rules | 0 |
| **Total** | **16** |

Findings by severity: 7 high, 4 medium, 5 low, 0 info. All 16 were found by the shell parser (high confidence); the line-based fallback was not needed.

Of the 7 GL007 findings, 4 were lowered to low severity because the report was uploaded to code scanning. The remaining non-gating Trivy runs wrote SARIF files that were never uploaded or checked, or were only archived as build artifacts.

## False positives fixed

One false-positive pattern was found and fixed:

- **A report written by a shell redirect and checked by a later command was reported at full severity.** A step ran a scanner with its soft-fail flag, redirected the output to a file (`> report.txt`), then ran `grep ... report.txt` and `exit $?`. The step does gate, on the report. gatelint now treats shell redirects (`>`, `>>`, `&>`) and `tee` arguments as report files, so the later check is recognised and the finding is lowered to low with an explanatory note. Fixture: `testdata/github/.github/workflows/redirect-report.yml`.

While investigating, a related GitLab case was added: scanner output published as an `artifacts:reports:sast` (or other security report) artifact is now treated like a SARIF upload and lowered one level, while output kept only as a plain artifact is not. Fixture: `testdata/gitlab/report-only/.gitlab-ci.yml`.

## Findings reviewed and kept

- Two high findings come from release smoke tests in a scanner's own repository, which run a freshly built binary with its soft-fail flag "to make sure it doesn't crash". gatelint is right that these steps cannot fail on findings; such deliberate cases should carry a `# gatelint:ignore GL006 <reason>` comment.
- Several findings come from a project that is deliberately insecure for training purposes, in a workflow that compares scanners. The findings are accurate; the gates are intentionally off.
- One finding is a scanner whose failure is swallowed with `|| true` while its JSON output is kept as a plain build artifact. Nothing gates on that output, so the finding stands.

## Notes produced

gatelint emitted 130 informational notes, none of them errors:

| Note | Count |
| --- | --- |
| Call to a remote reusable workflow (out of scope) | 71 |
| Local action or reusable workflow not found | 54 |
| Remote or project GitLab include (out of scope) | 2 |
| `extends:` of a job that is not defined in the scanned files | 2 |
| Unresolved `!reference` | 1 |

The "not found" notes are an artifact of the sparse checkout: local actions outside `.github/` were not fetched.

## Takeaways

- Most repositories that "run a scanner" rely on CodeQL or GitLab templates, which never fail a build by themselves; gatelint reports these as non-gating in the coverage summary without raising findings.
- The most common real gap was a scanner that does not gate by default (Trivy without `exit-code`) whose report was not consumed by anything.
- Common neutering patterns (`|| true`, `|| echo`, `continue-on-error: true`, soft-fail flags, `exit-code: '0'`) all appeared at least once.
