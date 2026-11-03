package suppress

import (
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

func TestParse(t *testing.T) {
	src := "a: 1 # gatelint:ignore GL001 because it is report-only\n" +
		"# gatelint:ignore GL001, gl004,GL006 -- nightly job only, gate lives elsewhere\n" +
		"b: 2\n" +
		"c: 3 #gatelint:ignore GL002\n" +
		"d: 4 # gatelint:ignore GL003 short\n" +
		"e: 5 # gatelint:ignore everything please\n" +
		"f: \"#gatelint:ignore inside a string without space\"\r\n" +
		"g: 6 # gatelint:ignore GL005: reason after a colon here\n"
	ds := Parse("ci.yml", []byte(src))
	if len(ds) != 6 {
		t.Fatalf("directives = %d: %+v", len(ds), ds)
	}
	if d := ds[0]; !d.Valid() || d.Line != 1 || d.Column != 6 || d.OwnLine || d.Rules[0] != "GL001" || d.Reason != "because it is report-only" {
		t.Errorf("same-line = %+v", d)
	}
	if d := ds[1]; !d.Valid() || !d.OwnLine || len(d.Rules) != 3 || d.Rules[1] != "GL004" || d.Reason != "nightly job only, gate lives elsewhere" {
		t.Errorf("own-line = %+v", d)
	}
	if d := ds[2]; d.Valid() || d.Problem != "has no reason" {
		t.Errorf("no reason = %+v", d)
	}
	if d := ds[3]; d.Valid() || d.Problem != "has a reason shorter than 10 characters" {
		t.Errorf("short = %+v", d)
	}
	if d := ds[4]; d.Valid() || d.Problem != "names no rule IDs" {
		t.Errorf("no ids = %+v", d)
	}
	if d := ds[5]; !d.Valid() || d.Reason != "reason after a colon here" {
		t.Errorf("colon = %+v", d)
	}
}

func TestApply(t *testing.T) {
	dirs := map[string][]Directive{"ci.yml": Parse("ci.yml", []byte(
		"x\n# gatelint:ignore GL001 tracked in SEC-1 until release\nline3\nline4 # gatelint:ignore GL004 tracked in SEC-2 until release\n# gatelint:ignore GL006\nline6\n"))}
	fs := []model.Finding{
		{RuleID: "GL001", File: "ci.yml", Line: 3}, // below own-line directive
		{RuleID: "GL001", File: "ci.yml", Line: 2}, // on the directive line
		{RuleID: "GL004", File: "ci.yml", Line: 4}, // same line
		{RuleID: "GL004", File: "ci.yml", Line: 5}, // below a trailing comment: no
		{RuleID: "GL002", File: "ci.yml", Line: 3}, // wrong rule
		{RuleID: "GL006", File: "ci.yml", Line: 6}, // invalid directive
		{RuleID: "GL001", File: "other.yml", Line: 3},
		{RuleID: "GL010", File: "ci.yml", Line: 2},
	}
	Apply(fs, dirs, "GL010")
	want := []bool{true, true, true, false, false, false, false, false}
	for i, w := range want {
		if fs[i].Suppressed != w {
			t.Errorf("finding %d (%s line %d) suppressed = %v, want %v", i, fs[i].RuleID, fs[i].Line, fs[i].Suppressed, w)
		}
	}
	if fs[0].SuppressionReason != "tracked in SEC-1 until release" {
		t.Errorf("reason = %q", fs[0].SuppressionReason)
	}
}
