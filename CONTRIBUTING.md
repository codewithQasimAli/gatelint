# Contributing

Thanks for helping make CI security gates harder to switch off. Bug reports with a minimal YAML snippet are the most useful contribution of all.

## Development setup

You need Go 1.24 or newer and, for linting, golangci-lint v2.

```bash
git clone https://github.com/codewithQasimAli/gatelint
```

```bash
cd gatelint && go test ./...
```

Before sending a change, run the same checks as CI:

```bash
gofmt -l .
```

```bash
go vet ./...
```

```bash
go test -race ./...
```

```bash
golangci-lint run
```

```bash
go run ./cmd/gatelint scan .
```

`gofmt -l .` must print nothing, and the last command must exit 0.

## Layout

| Path | Contents |
| --- | --- |
| `cmd/gatelint` | `main`, which only calls `internal/cli` |
| `internal/cli` | command line, exit codes, golden tests |
| `internal/scan` | file discovery, configuration, wiring |
| `internal/github`, `internal/gitlab` | parsers into `internal/model` |
| `internal/shell` | shell analysis of `run:` and `script:` blocks |
| `internal/catalog` | scanner catalog (`default.yml`) and flag evaluation |
| `internal/rules` | one file per rule, coverage, report-only mitigation |
| `internal/suppress` | `# gatelint:ignore` comments |
| `internal/report` | table, JSON, SARIF, Code Quality |
| `testdata/github`, `testdata/gitlab` | fixtures; outputs in `testdata/golden` |

## Golden files

`testdata/golden` holds the expected output of `gatelint scan testdata/github` and `gatelint scan testdata/gitlab` in every format, and of the README example. After an intended change in output:

```bash
go test ./internal/cli -update
```

Then review the diff of `testdata/golden` (and copy the new example output into README.md if it changed; a test checks that they match).

## Adding a scanner

Most scanners need no Go code. Add an entry to `internal/catalog/default.yml`:

```yaml
  - id: mytool
    name: MyTool
    commands: [mytool]              # command words; multi-word such as "npm audit" works
    python-modules: []              # for python -m
    packages: []                    # for pipx run, uvx, npx and similar
    images: [example/mytool]        # for docker run and docker:// actions
    skip-flags: [--version, --help]
    output-flags: [--output, -o]    # report files, used for report-only detection
    fail-exit-codes: [1]
    modes:
      - gates-by-default: true
    settings:
      - names: [--no-fail]
        neuter-when: set            # set, zero, nonzero, any, true, false
        description: exits 0 even when issues are found
    actions:
      - uses: example/mytool-action
        gates-by-default: true
        inputs:
          - names: [soft-fail]
            neuter-when: "true"
            description: keeps the step green whatever is found
```

Then:

1. Verify every default against the tool's documentation or source, and add the source to the table in `docs/DECISIONS.md`.
2. Add true-positive and false-positive cases to `internal/catalog/catalog_test.go` and to the relevant rule tests in `internal/rules/rules_test.go`.
3. Add a fixture under `testdata/` if the scanner has a pattern not covered yet, and update the golden files.

Users can add the same entries to `.gatelint.yml` under `scanners:` without changing gatelint.

## Adding a rule

1. Create `internal/rules/glNNN.go` with a `register(&Rule{...})` call: ID, title, severity, platforms, a one-paragraph explanation of the risk, a one-line hint, and before/after YAML. Wire the check in `init()`.
2. Write the check against `ctx.Uses` (one entry per scanner invocation, with the parsed shell context and the catalog evaluation). Use `rule.finding(...)` so findings carry job, step, scanner and confidence.
3. If the rule means the scanner cannot gate, add its ID to `neutering` in `mitigate.go` so coverage and report-only handling pick it up.
4. Add a table-driven test with at least three true positives and two false positives, on both platforms where the rule applies.
5. Generate the documentation page and check it:

```bash
go test ./internal/rules -run TestRuleDocs -update
```

6. Add the rule to the table in README.md and update the golden files.

## Commit messages

Use short imperative subjects with a type prefix: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`.
