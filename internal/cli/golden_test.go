package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGolden runs "gatelint scan testdata/<platform>" from the repository
// root in every output format and compares the output with the golden files
// in testdata/golden. Run "go test ./internal/cli -update" to regenerate.
func TestGolden(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, platform := range []string{"github", "gitlab"} {
		for _, format := range []string{"table", "json", "sarif", "codequality"} {
			t.Run(platform+"/"+format, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Run([]string{"scan", "testdata/" + platform, "--format", format}, &stdout, &stderr, BuildInfo{Version: "dev"})
				if code != ExitFindings {
					t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr.String())
				}
				if stderr.Len() > 0 {
					t.Errorf("unexpected stderr: %s", stderr.String())
				}
				if format != "table" && !json.Valid(stdout.Bytes()) {
					t.Fatalf("%s output is not valid JSON", format)
				}
				golden := filepath.Join("testdata", "golden", platform+"."+format)
				if *update {
					if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("read golden file (run with -update to create it): %v", err)
				}
				if !bytes.Equal(stdout.Bytes(), want) {
					t.Errorf("output differs from %s; run go test ./internal/cli -update and review the diff\n--- got ---\n%s", golden, stdout.String())
				}
			})
		}
	}
}

// TestReadmeExample checks that the example output in README.md is exactly
// what "gatelint scan testdata/example" prints.
func TestReadmeExample(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", "testdata/example"}, &stdout, &stderr, BuildInfo{Version: "dev"})
	if code != ExitFindings {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
	}
	golden := filepath.Join("testdata", "golden", "example.table")
	if *update {
		if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("example output differs from %s; run go test ./internal/cli -update", golden)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	block := "```text\n$ gatelint scan testdata/example\n" + stdout.String() + "```"
	if !strings.Contains(string(readme), block) {
		t.Errorf("README.md does not contain the current example output:\n%s", block)
	}
}
