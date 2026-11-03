# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- `gatelint scan` for GitHub Actions workflows, composite actions and GitLab CI
  configuration, with automatic file discovery, local GitLab includes,
  `extends:`, YAML anchors and merge keys, `!reference` tags, local reusable
  workflows and local actions.
- Shell analysis built on a syntax tree: `|| true` and similar, negation,
  `&&` lists, command substitution, background jobs, if conditions, `set +e`,
  pipefail, `bash -c`, inline and exported environment variables, and a
  line-based fallback for scripts that do not parse.
- Data-driven scanner catalog: Bandit, Trivy, Grype, Semgrep, Gitleaks,
  Checkov, tfsec, npm/pnpm/yarn audit, pip-audit, Snyk, CodeQL, gosec,
  TruffleHog, gatelint, and GitLab security templates, extendable in
  `.gatelint.yml`.
- Rules GL001 to GL010, each documented in `docs/rules`.
- Gate coverage summary per file.
- Inline suppressions that require a reason.
- Report formats: table, JSON, SARIF 2.1.0 and GitLab Code Quality.
- `gatelint rules` and `gatelint version`.
- Composite GitHub Action, GitLab CI template, Dockerfile and GoReleaser
  configuration.
