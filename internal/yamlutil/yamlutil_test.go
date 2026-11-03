package yamlutil

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	got := string(Normalize([]byte("\xef\xbb\xbfa\r\nb\rc\n")))
	if got != "a\nb\nc\n" {
		t.Errorf("Normalize = %q", got)
	}
}

func TestPairsMergeKeys(t *testing.T) {
	doc, err := Parse("x.yml", []byte(`a: &a {k1: 1, k2: 2}
b: &b {k3: 3}
c:
  <<: [*a, *b]
  k2: override
d:
  <<: *a
e: *a
`))
	if err != nil {
		t.Fatal(err)
	}
	root, err := doc.RootMapping()
	if err != nil {
		t.Fatal(err)
	}
	c := Get(root, "c")
	if ScalarString(Get(c, "k1")) != "1" || ScalarString(Get(c, "k2")) != "override" || ScalarString(Get(c, "k3")) != "3" {
		t.Errorf("merged = %v", Pairs(c))
	}
	if ScalarString(Get(Get(root, "d"), "k2")) != "2" || ScalarString(Get(Get(root, "e"), "k1")) != "1" {
		t.Error("alias resolution failed")
	}
	if Get(root, "missing") != nil || Get(nil, "x") != nil {
		t.Error("missing key returned a node")
	}
	if _, ok := GetPair(root, "missing"); ok {
		t.Error("GetPair found a missing key")
	}
	if pr, ok := GetPair(root, "a"); !ok || pr.Key.Line != 1 {
		t.Error("GetPair failed")
	}
	if !strings.Contains(ScalarString(c), "k2: override") {
		t.Errorf("ScalarString(mapping) = %q", ScalarString(c))
	}
	if ScalarString(nil) != "" {
		t.Error("ScalarString(nil)")
	}
}

func TestStringListAndKinds(t *testing.T) {
	doc, err := Parse("x.yml", []byte("s: one\nl: [a, b, {c: d}]\nn: ~\nm: {a: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := doc.RootMapping()
	if got := StringList(Get(root, "s")); len(got) != 1 || got[0] != "one" {
		t.Errorf("scalar list = %v", got)
	}
	if got := StringList(Get(root, "l")); len(got) != 2 {
		t.Errorf("seq list = %v", got)
	}
	if StringList(Get(root, "n")) != nil || StringList(Get(root, "m")) != nil || StringList(nil) != nil {
		t.Error("expected nil lists")
	}
	if !IsMapping(Get(root, "m")) || !IsSequence(Get(root, "l")) || !IsScalar(Get(root, "s")) {
		t.Error("kind helpers")
	}
	v := doc.Value(nil, Get(root, "s"))
	if !v.Set || v.Raw != "one" || v.Pos.Line != 1 || v.Pos.File != "x.yml" {
		t.Errorf("Value = %+v", v)
	}
	if v := doc.Value(nil, nil); v.Set {
		t.Error("Value(nil) set")
	}
	if p := doc.Pos(nil); p.File != "x.yml" || p.Line != 0 {
		t.Errorf("Pos(nil) = %+v", p)
	}
}

func TestSegmentBlockIndent(t *testing.T) {
	doc, err := Parse("x.yml", []byte("run: |\n\n    first\n      second\nfolded: >\n  a\n  b\n"))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := doc.RootMapping()
	seg := doc.Segment(Get(root, "run"))
	if seg.Pos.Line != 2 || seg.Pos.Column != 5 || seg.ContColumn != 5 {
		t.Errorf("literal segment = %+v", seg)
	}
	seg = doc.Segment(Get(root, "folded"))
	if seg.Pos.Line != 6 || seg.Pos.Column != 3 {
		t.Errorf("folded segment = %+v", seg)
	}
}

func TestRootMapping(t *testing.T) {
	for _, src := range []string{"", "~\n"} {
		doc, err := Parse("x", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if r, err := doc.RootMapping(); r != nil || err != nil {
			t.Errorf("%q: %v %v", src, r, err)
		}
	}
	doc, _ := Parse("x", []byte("[1, 2]\n"))
	if _, err := doc.RootMapping(); err == nil {
		t.Error("sequence root accepted")
	}
}

func TestParseErrors(t *testing.T) {
	_, err := Parse("x", []byte("a:\n\tb: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "tab characters") || !strings.HasPrefix(err.Error(), "invalid YAML: line 2") {
		t.Errorf("tab error = %v", err)
	}
	_, err = Parse("x", []byte("a: [1\n"))
	if err == nil || strings.Contains(err.Error(), "tab") {
		t.Errorf("bracket error = %v", err)
	}
}
