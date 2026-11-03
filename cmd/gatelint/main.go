// Command gatelint finds neutered security gates in GitHub Actions and GitLab
// CI configuration.
package main

import (
	"os"

	"github.com/codewithQasimAli/gatelint/internal/cli"
)

// Set with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
