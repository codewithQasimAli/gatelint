package gitlab

import (
	"gopkg.in/yaml.v3"

	"github.com/codewithQasimAli/gatelint/internal/yamlutil"
)

// maxDepth bounds recursion through nested mappings, extends chains and
// references.
const maxDepth = 32

// mval is a YAML value that remembers the document it came from, so values
// merged from several files (includes, extends) keep exact positions.
type mval struct {
	doc  *yamlutil.Doc
	key  *yaml.Node // the key node under which the value was defined
	node *yaml.Node // the resolved value node
	keys []string
	m    map[string]*mval
}

func (v *mval) isMap() bool { return v != nil && v.m != nil }

func (v *mval) get(key string) *mval {
	if v == nil || v.m == nil {
		return nil
	}
	return v.m[key]
}

// fromNode converts a YAML node into an mval tree, resolving aliases and
// merge keys. Tagged nodes such as !reference are kept as leaves.
func fromNode(doc *yamlutil.Doc, key, n *yaml.Node, depth int) *mval {
	n = yamlutil.Resolve(n)
	if n == nil {
		return nil
	}
	v := &mval{doc: doc, key: key, node: n}
	if n.Kind != yaml.MappingNode || depth > maxDepth {
		return v
	}
	v.m = map[string]*mval{}
	for _, p := range yamlutil.Pairs(n) {
		k := p.Key.Value
		if _, seen := v.m[k]; !seen {
			v.keys = append(v.keys, k)
		}
		v.m[k] = fromNode(doc, p.Key, p.Value, depth+1)
	}
	return v
}

// merge deep-merges src over dst the way GitLab merges included files and
// extends: mappings merge key by key, everything else is replaced.
func merge(dst, src *mval) *mval {
	return mergeDepth(dst, src, 0)
}

func mergeDepth(dst, src *mval, depth int) *mval {
	if dst == nil {
		return src
	}
	if src == nil {
		return dst
	}
	if !dst.isMap() || !src.isMap() || depth > maxDepth {
		return src
	}
	out := &mval{doc: src.doc, key: src.key, node: src.node, m: map[string]*mval{}}
	for _, k := range dst.keys {
		out.keys = append(out.keys, k)
		out.m[k] = dst.m[k]
	}
	for _, k := range src.keys {
		if existing, ok := out.m[k]; ok {
			out.m[k] = mergeDepth(existing, src.m[k], depth+1)
			continue
		}
		out.keys = append(out.keys, k)
		out.m[k] = src.m[k]
	}
	return out
}

// without returns a shallow copy of a mapping without the given key.
func (v *mval) without(key string) *mval {
	if !v.isMap() {
		return v
	}
	out := &mval{doc: v.doc, key: v.key, node: v.node, m: map[string]*mval{}}
	for _, k := range v.keys {
		if k == key {
			continue
		}
		out.keys = append(out.keys, k)
		out.m[k] = v.m[k]
	}
	return out
}
