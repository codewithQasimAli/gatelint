package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/codewithQasimAli/gatelint/internal/catalog"
	"github.com/codewithQasimAli/gatelint/internal/rules"
)

// ConfigNames are the configuration files looked up automatically.
var ConfigNames = []string{".gatelint.yml", ".gatelint.yaml"}

// Config is the optional project configuration (.gatelint.yml).
type Config struct {
	// FailOn sets the default for --fail-on.
	FailOn string `yaml:"fail-on"`
	// DisableRules turns rules off by ID.
	DisableRules []string `yaml:"disable-rules"`
	// Exclude lists path globs (relative, "**" allowed) to skip.
	Exclude []string `yaml:"exclude"`
	// Scanners adds catalog entries or replaces built-in ones by id.
	Scanners []*catalog.Tool `yaml:"scanners"`
	// GitLabTemplates adds or replaces GitLab template entries.
	GitLabTemplates []*catalog.GitLabTemplate `yaml:"gitlab-templates"`

	// Path is the file the configuration was read from.
	Path string `yaml:"-"`
}

// LoadConfig reads a configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(strings.ReplaceAll(string(data), "\r\n", "\n")))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.Path = path
	if c.FailOn != "" {
		switch strings.ToLower(c.FailOn) {
		case "high", "medium", "low", "none":
		default:
			return nil, fmt.Errorf("config %s: fail-on must be high, medium, low or none", path)
		}
	}
	for _, id := range c.DisableRules {
		if rules.ByID(id) == nil {
			return nil, fmt.Errorf("config %s: disable-rules names unknown rule %q", path, id)
		}
	}
	if len(c.Scanners) > 0 || len(c.GitLabTemplates) > 0 {
		extra := &catalog.Catalog{Tools: c.Scanners, Templates: c.GitLabTemplates}
		if err := extra.Validate(); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	return &c, nil
}

// FindConfig returns the first configuration file found in dir.
func FindConfig(dir string) string {
	for _, n := range ConfigNames {
		p := filepath.Join(dir, n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// excluder matches display paths against exclude globs.
type excluder []*regexp.Regexp

func newExcluder(globs []string) excluder {
	var out excluder
	for _, g := range globs {
		g = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(g)), "./")
		if g == "" {
			continue
		}
		out = append(out, globToRegexp(g))
	}
	return out
}

func (e excluder) match(p string) bool {
	p = strings.TrimPrefix(p, "./")
	for _, re := range e {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// globToRegexp converts a path glob into an anchored regular expression.
// "*" matches within a path segment and "**" across segments. A pattern
// that matches a directory also matches everything below it.
func globToRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
			if i+1 < len(pattern) && pattern[i+1] == '/' {
				b.WriteString("/?")
				i++
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("(/.*)?$")
	return regexp.MustCompile(b.String())
}
