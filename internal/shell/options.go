package shell

import (
	"path"
	"strings"
)

// GitHubOptions returns the shell options GitHub Actions uses for a run step.
// shellValue is the effective "shell:" setting ("" when omitted) and windows
// reports whether the job runs on a Windows runner.
//
// Per the GitHub documentation: an omitted shell on Linux and macOS runs
// "bash -e {0}" (errexit, no pipefail); "shell: bash" runs
// "bash --noprofile --norc -eo pipefail {0}"; "shell: sh" runs "sh -e {0}";
// Windows defaults to pwsh.
func GitHubOptions(shellValue string, windows bool) Options {
	s := strings.TrimSpace(shellValue)
	switch strings.ToLower(s) {
	case "":
		if windows {
			return Options{Dialect: PowerShell, Errexit: true, Pipefail: true, ShellDesc: "pwsh"}
		}
		return Options{Dialect: Bash, Errexit: true, ShellDesc: "bash -e {0}"}
	case "bash":
		return Options{Dialect: Bash, Errexit: true, Pipefail: true, ShellDesc: "bash --noprofile --norc -eo pipefail {0}"}
	case "sh":
		return Options{Dialect: POSIX, Errexit: true, ShellDesc: "sh -e {0}"}
	case "pwsh", "powershell":
		return Options{Dialect: PowerShell, Errexit: true, Pipefail: true, ShellDesc: s}
	case "cmd", "python":
		return Options{Dialect: Other, Errexit: true, Pipefail: true, ShellDesc: s}
	}
	return CustomOptions(s)
}

// CustomOptions parses a custom shell command such as "bash -eo pipefail {0}".
func CustomOptions(s string) Options {
	f := strings.Fields(s)
	if len(f) == 0 {
		return Options{Dialect: Bash, Errexit: true}
	}
	base := path.Base(f[0])
	o := Options{ShellDesc: s}
	switch base {
	case "bash", "zsh", "ksh":
		o.Dialect = Bash
	case "sh", "dash", "ash", "busybox":
		o.Dialect = POSIX
	case "pwsh", "powershell":
		return Options{Dialect: PowerShell, Errexit: true, Pipefail: true, ShellDesc: s}
	default:
		return Options{Dialect: Other, Errexit: true, Pipefail: true, ShellDesc: s}
	}
	for i := 1; i < len(f); i++ {
		a := f[i]
		switch {
		case a == "-o" || a == "+o":
			if i+1 < len(f) {
				switch f[i+1] {
				case "pipefail":
					o.Pipefail = a == "-o"
				case "errexit":
					o.Errexit = a == "-o"
				}
				i++
			}
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			if strings.Contains(a, "e") {
				o.Errexit = true
			}
			if strings.HasSuffix(a, "o") && i+1 < len(f) && f[i+1] == "pipefail" {
				o.Pipefail = true
				i++
			}
		}
	}
	return o
}

// GitLabOptions returns the options GitLab Runner uses for job scripts. The
// runner's bash and sh shells enable errexit and, where the shell supports
// it, pipefail before running the job script.
func GitLabOptions() Options {
	return Options{Dialect: Bash, Errexit: true, Pipefail: true, ShellDesc: "GitLab Runner shell"}
}
