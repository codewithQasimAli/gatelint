// Package cli implements the gatelint command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/report"
	"github.com/codewithQasimAli/gatelint/internal/rules"
	"github.com/codewithQasimAli/gatelint/internal/scan"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// BuildInfo is set by the main package from -ldflags.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// resolve fills in the module version for "go install" builds.
func (b BuildInfo) resolve() BuildInfo {
	if b.Version == "" {
		b.Version = "dev"
	}
	if b.Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && isRelease(info.Main.Version) {
			b.Version = strings.TrimPrefix(info.Main.Version, "v")
		}
	}
	if b.Commit == "" {
		b.Commit = "none"
	}
	if b.Date == "" {
		b.Date = "unknown"
	}
	return b
}

var pseudoVersion = regexp.MustCompile(`\d{14}-[0-9a-f]{12}`)

// isRelease reports whether a module version is a tagged release, as set by
// "go install ...@v1.2.3", rather than a VCS pseudo-version stamped into
// local builds.
func isRelease(v string) bool {
	return strings.HasPrefix(v, "v") && !strings.Contains(v, "+dirty") && !pseudoVersion.MatchString(v)
}

// exitError carries an exit code through cobra.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

// IsTerminal reports whether w is a character device; it can be replaced in
// tests.
var IsTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Run executes the command line and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer, info BuildInfo) int {
	info = info.resolve()
	root := newRoot(stdout, stderr, info)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			_, _ = fmt.Fprintf(stderr, "gatelint: %v\n", ee.err)
		}
		return ee.code
	}
	_, _ = fmt.Fprintf(stderr, "gatelint: %v\n", err)
	return ExitError
}

func newRoot(stdout, stderr io.Writer, info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "gatelint",
		Short:         "Find neutered security gates in GitHub Actions and GitLab CI",
		Long:          "gatelint finds CI security scanners that can never fail a build (|| true, continue-on-error,\nallow_failure, --exit-zero, --soft-fail, disabled jobs) and explains how to fix them.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return &exitError{code: ExitError, err: fmt.Errorf("%w\nRun '%s --help' for usage", err, c.CommandPath())}
	})
	root.AddCommand(newScan(stdout, stderr, info), newRules(stdout), newVersion(stdout, info))
	return root
}

type scanFlags struct {
	format   string
	output   string
	failOn   string
	platform string
	config   string
	noColor  bool
	quiet    bool
}

func newScan(stdout, stderr io.Writer, info BuildInfo) *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan CI configuration for neutered security gates",
		Long: `Scan files and directories (default ".") for GitHub Actions workflows, composite
actions and GitLab CI files, and report security scanners that cannot fail the build.

Exit codes: 0 no findings at or above --fail-on, 1 findings at or above --fail-on,
2 usage, parse or I/O error.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, f, stdout, stderr, info)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.format, "format", "table", "output format: table, json, sarif or codequality")
	fl.StringVarP(&f.output, "output", "o", "", "write the report to `FILE` instead of stdout")
	fl.StringVar(&f.failOn, "fail-on", "high", "exit 1 when findings at or above this severity exist: high, medium, low or none")
	fl.StringVar(&f.platform, "platform", "auto", "which CI files to scan: auto, github or gitlab")
	fl.StringVar(&f.config, "config", "", "read configuration from `FILE` (default: .gatelint.yml in the first path)")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colored output")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "print findings only (table format) and no warnings")
	return cmd
}

func usageErr(format string, a ...any) error {
	return &exitError{code: ExitError, err: fmt.Errorf(format, a...)}
}

func runScan(cmd *cobra.Command, args []string, f scanFlags, stdout, stderr io.Writer, info BuildInfo) error {
	format := strings.ToLower(f.format)
	valid := false
	for _, x := range report.Formats {
		if x == format {
			valid = true
		}
	}
	if !valid {
		return usageErr("invalid --format %q (want %s)", f.format, strings.Join(report.Formats, ", "))
	}
	switch strings.ToLower(f.platform) {
	case "auto", "github", "gitlab":
	default:
		return usageErr("invalid --platform %q (want auto, github or gitlab)", f.platform)
	}

	opts := scan.Options{Platform: strings.ToLower(f.platform)}
	if f.config != "" {
		cfg, err := scan.LoadConfig(f.config)
		if err != nil {
			return &exitError{code: ExitError, err: err}
		}
		opts.Config = cfg
	}
	res, cfg, err := scan.Run(args, opts)
	if err != nil {
		return &exitError{code: ExitError, err: err}
	}

	failOn := f.failOn
	if !cmd.Flags().Changed("fail-on") && cfg != nil && cfg.FailOn != "" {
		failOn = cfg.FailOn
	}
	threshold, fail, err := parseFailOn(failOn)
	if err != nil {
		return usageErr("%v", err)
	}

	out := stdout
	var file *os.File
	if f.output != "" {
		file, err = os.Create(f.output)
		if err != nil {
			return &exitError{code: ExitError, err: err}
		}
		out = file
	}
	color := !f.noColor && f.output == "" && os.Getenv("NO_COLOR") == "" && IsTerminal(stdout)
	werr := report.Write(out, format, res, report.Options{Color: color, Quiet: f.quiet, Version: info.Version})
	if file != nil {
		if cerr := file.Close(); werr == nil {
			werr = cerr
		}
	}
	if werr != nil {
		return &exitError{code: ExitError, err: werr}
	}
	for _, e := range res.Errors {
		_, _ = fmt.Fprintf(stderr, "gatelint: error: %s: %s\n", e.File, e.Message)
	}
	if len(res.Errors) > 0 {
		return &exitError{code: ExitError}
	}
	if fail && res.FailsAt(threshold) {
		return &exitError{code: ExitFindings}
	}
	return nil
}

func parseFailOn(s string) (model.Severity, bool, error) {
	switch strings.ToLower(s) {
	case "none":
		return model.High, false, nil
	case "high", "medium", "low":
		sev, _ := model.ParseSeverity(s)
		return sev, true, nil
	}
	return model.High, false, fmt.Errorf("invalid --fail-on %q (want high, medium, low or none)", s)
}

func newRules(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "rules [rule-id]",
		Short: "List rules, or describe one rule",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				r := rules.ByID(args[0])
				if r == nil {
					return usageErr("unknown rule %q", args[0])
				}
				_, _ = fmt.Fprintf(stdout, "%s  %s  (%s)\nPlatforms: %s\n\n%s\n\nFix: %s\n\nBefore:\n%s\n\nAfter:\n%s\n\nDocs: %s\n",
					r.ID, r.Title, r.Severity.Upper(), r.Platforms, r.Explanation, r.Hint,
					indent(r.Before), indent(r.After), r.HelpURI())
				return nil
			}
			var b strings.Builder
			tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tSEVERITY\tPLATFORMS\tTITLE")
			for _, r := range rules.All() {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Severity.Upper(), r.Platforms, r.Title)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			_, err := io.WriteString(stdout, b.String())
			return err
		},
	}
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

func newVersion(stdout io.Writer, info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = fmt.Fprintf(stdout, "gatelint %s\ncommit: %s\nbuilt:  %s\n", info.Version, info.Commit, info.Date)
			return nil
		},
	}
}
