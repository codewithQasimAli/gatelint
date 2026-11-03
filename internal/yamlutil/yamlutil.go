// Package yamlutil wraps gopkg.in/yaml.v3 node handling: it normalises line
// endings, resolves aliases and merge keys, and maps scalar values back to
// exact source positions.
package yamlutil

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

// maxDepth bounds alias resolution and recursive merges.
const maxDepth = 64

// Doc is a parsed YAML document plus its source lines.
type Doc struct {
	Path  string
	Root  *yaml.Node // the top-level node (usually a mapping); nil for empty files
	Lines []string
}

// Normalize converts CRLF and CR line endings to LF and strips a UTF-8 BOM.
func Normalize(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
}

var lineRe = regexp.MustCompile(`line (\d+)`)

// Parse parses data as a single YAML document. Errors include the path and,
// where YAML forbids it, a hint about tab indentation.
func Parse(path string, data []byte) (*Doc, error) {
	data = Normalize(data)
	doc := &Doc{Path: path, Lines: strings.Split(string(data), "\n")}
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		msg := strings.TrimPrefix(err.Error(), "yaml: ")
		if m := lineRe.FindStringSubmatch(msg); m != nil {
			if ln, convErr := strconv.Atoi(m[1]); convErr == nil && ln >= 1 && ln <= len(doc.Lines) &&
				strings.HasPrefix(strings.TrimLeft(doc.Lines[ln-1], " "), "\t") {
				msg += " (YAML does not allow tab characters for indentation)"
			}
		}
		return nil, errors.New("invalid YAML: " + msg)
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		doc.Root = n.Content[0]
	}
	return doc, nil
}

// Resolve follows alias nodes to their target.
func Resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < maxDepth; i++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

// Pair is a key/value entry of a mapping.
type Pair struct {
	Key   *yaml.Node
	Value *yaml.Node
}

// Pairs returns the entries of a mapping node, resolving aliases and "<<"
// merge keys. Explicit keys override merged ones; merged keys keep their
// original positions.
func Pairs(n *yaml.Node) []Pair {
	return pairs(n, 0)
}

func pairs(n *yaml.Node, depth int) []Pair {
	n = Resolve(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > maxDepth {
		return nil
	}
	var merged, own []Pair
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" || (k.Value == "<<" && k.Style == 0) {
			src := Resolve(v)
			if src == nil {
				continue
			}
			if src.Kind == yaml.SequenceNode {
				for _, item := range src.Content {
					merged = mergeInto(merged, pairs(item, depth+1))
				}
			} else {
				merged = mergeInto(merged, pairs(src, depth+1))
			}
			continue
		}
		own = append(own, Pair{Key: k, Value: v})
	}
	if len(merged) == 0 {
		return own
	}
	return mergeInto(merged, own)
}

// mergeInto appends pairs from src to dst, replacing entries with equal keys.
func mergeInto(dst, src []Pair) []Pair {
	for _, p := range src {
		replaced := false
		for i := range dst {
			if dst[i].Key.Value == p.Key.Value {
				dst[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			dst = append(dst, p)
		}
	}
	return dst
}

// Get returns the value for key in a mapping node, or nil.
func Get(n *yaml.Node, key string) *yaml.Node {
	for _, p := range Pairs(n) {
		if p.Key.Value == key {
			return Resolve(p.Value)
		}
	}
	return nil
}

// GetPair returns the key and value nodes for key in a mapping node.
func GetPair(n *yaml.Node, key string) (Pair, bool) {
	for _, p := range Pairs(n) {
		if p.Key.Value == key {
			return Pair{Key: p.Key, Value: Resolve(p.Value)}, true
		}
	}
	return Pair{}, false
}

// IsScalar reports whether n is a scalar node.
func IsScalar(n *yaml.Node) bool { return n != nil && n.Kind == yaml.ScalarNode }

// IsMapping reports whether n is a mapping node.
func IsMapping(n *yaml.Node) bool { return n != nil && n.Kind == yaml.MappingNode }

// IsSequence reports whether n is a sequence node.
func IsSequence(n *yaml.Node) bool { return n != nil && n.Kind == yaml.SequenceNode }

// Pos returns the position of a node.
func (d *Doc) Pos(n *yaml.Node) model.Pos {
	if n == nil {
		return model.Pos{File: d.Path}
	}
	return model.Pos{File: d.Path, Line: n.Line, Column: n.Column}
}

// Value converts a scalar node to a model.Value positioned at the key.
func (d *Doc) Value(key, val *yaml.Node) model.Value {
	val = Resolve(val)
	if val == nil {
		return model.Value{}
	}
	pos := d.Pos(key)
	if key == nil {
		pos = d.Pos(val)
	}
	return model.Value{Raw: ScalarString(val), Set: true, Pos: pos}
}

// ScalarString returns the scalar value of n, or a compact rendering of
// non-scalar nodes.
func ScalarString(n *yaml.Node) string {
	n = Resolve(n)
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	out, err := yaml.Marshal(n)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Segment maps a scalar node holding shell code to a model.Segment whose
// position is that of the first character of the script.
func (d *Doc) Segment(n *yaml.Node) model.Segment {
	n = Resolve(n)
	seg := model.Segment{Text: n.Value, Pos: model.Pos{File: d.Path, Line: n.Line, Column: n.Column}}
	switch n.Style {
	case yaml.LiteralStyle, yaml.FoldedStyle:
		seg.Pos.Line = n.Line + 1
		indent := d.blockIndent(n)
		seg.Pos.Column = indent + 1
		seg.ContColumn = indent + 1
	case yaml.DoubleQuotedStyle, yaml.SingleQuotedStyle:
		seg.Pos.Column = n.Column + 1
		seg.ContColumn = seg.Pos.Column
	default:
		seg.ContColumn = n.Column
	}
	return seg
}

// blockIndent computes the indentation stripped from a block scalar by
// comparing the first non-blank source line with the first non-blank value
// line.
func (d *Doc) blockIndent(n *yaml.Node) int {
	valLines := strings.Split(n.Value, "\n")
	for i, vl := range valLines {
		if strings.TrimSpace(vl) == "" {
			continue
		}
		idx := n.Line + i // 0-based index of source line n.Line+1+i
		if idx < 0 || idx >= len(d.Lines) {
			return 0
		}
		src := d.Lines[idx]
		srcIndent := len(src) - len(strings.TrimLeft(src, " \t"))
		valIndent := len(vl) - len(strings.TrimLeft(vl, " \t"))
		if srcIndent >= valIndent {
			return srcIndent - valIndent
		}
		return srcIndent
	}
	return 0
}

// ErrNotMapping is returned when a document's root is not a mapping.
var ErrNotMapping = errors.New("top-level YAML value is not a mapping")

// RootMapping returns the root mapping or an error for non-empty files whose
// root is something else.
func (d *Doc) RootMapping() (*yaml.Node, error) {
	if d.Root == nil {
		return nil, nil
	}
	r := Resolve(d.Root)
	if r == nil {
		return nil, nil
	}
	if r.Kind == yaml.ScalarNode && r.Tag == "!!null" {
		return nil, nil
	}
	if r.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w (line %d)", ErrNotMapping, r.Line)
	}
	return r, nil
}

// StringList converts a scalar or a sequence of scalars into strings.
func StringList(n *yaml.Node) []string {
	n = Resolve(n)
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil
		}
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			if c = Resolve(c); c != nil && c.Kind == yaml.ScalarNode {
				out = append(out, c.Value)
			}
		}
		return out
	}
	return nil
}
