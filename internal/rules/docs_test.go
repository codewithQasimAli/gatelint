package rules_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/rules"
)

var updateDocs = flag.Bool("update", false, "rewrite docs/rules from the rule metadata")

// ruleDoc renders the documentation page of a rule.
func ruleDoc(r *rules.Rule) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s: %s\n\n", r.ID, r.Title)
	fmt.Fprintf(&b, "| Severity | Platforms |\n| --- | --- |\n| %s | %s |\n\n", r.Severity.Upper(), r.Platforms)
	fmt.Fprintf(&b, "## Risk\n\n%s\n\n", r.Explanation)
	fmt.Fprintf(&b, "## Fix\n\n%s.\n\nBefore:\n\n```yaml\n%s\n```\n\nAfter:\n\n```yaml\n%s\n```\n\n", capitalize(r.Hint), r.Before, r.After)
	if r.ID != rules.Exempt {
		fmt.Fprintf(&b, "## Suppressing\n\nIf the finding is a deliberate exception, suppress it on the same line or the line directly above, with a reason of at least 10 characters:\n\n```yaml\n# gatelint:ignore %s <why this is acceptable and where the real gate is>\n```\n\n", r.ID)
	}
	fmt.Fprintf(&b, "See the [rule index](../../README.md#rules) for the other rules. `gatelint rules %s` prints this description in the terminal.\n", r.ID)
	return b.Bytes()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}

// TestRuleDocs keeps docs/rules/GL0xx.md in sync with the rule metadata.
// Run "go test ./internal/rules -run TestRuleDocs -update" after changing a
// rule's description.
func TestRuleDocs(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "rules")
	for _, r := range rules.All() {
		path := filepath.Join(dir, r.ID+".md")
		want := ruleDoc(r)
		if *updateDocs {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", r.ID, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date; run go test ./internal/rules -run TestRuleDocs -update", path)
		}
	}
}
