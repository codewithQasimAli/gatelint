package model

import (
	"encoding/json"
	"testing"
)

func TestSeverity(t *testing.T) {
	for _, name := range []string{"info", "low", "medium", "HIGH"} {
		s, err := ParseSeverity(name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(s)
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Errorf("round trip %s: %v %v", name, back, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("unknown severity parsed")
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("bogus severity unmarshalled")
	}
	if err := json.Unmarshal([]byte(`1`), &s); err == nil {
		t.Error("numeric severity unmarshalled")
	}
	if Severity(9).String() != "unknown" || High.Upper() != "HIGH" {
		t.Error("String/Upper")
	}
	if High.Lower() != Medium || Low.Lower() != Low || Info.Lower() != Info {
		t.Error("Lower")
	}
}

func TestPosAndValue(t *testing.T) {
	if (Pos{File: "a", Line: 2, Column: 3}).String() != "a:2:3" || (Pos{File: "a", Line: 2}).String() != "a:2" {
		t.Error("Pos.String")
	}
	if !(Pos{}).IsZero() {
		t.Error("IsZero")
	}
	if !(Value{Raw: "${{ x }}"}).IsExpression() || (Value{Raw: "x"}).IsExpression() {
		t.Error("IsExpression")
	}
}

func TestFindingHelpers(t *testing.T) {
	f := Finding{File: "a.yml", Line: 3, Job: "j", Step: "s"}
	if f.Location() != "a.yml:3" || f.Where() != "j / s" {
		t.Error("Location/Where")
	}
	if (Finding{Job: "j"}).Where() != "j" || (Finding{Step: "s"}).Where() != "s" {
		t.Error("Where partial")
	}
	if (FileError{File: "a", Message: "b"}).Error() != "a: b" {
		t.Error("FileError")
	}
	r := &Result{Findings: []Finding{{Severity: High, Suppressed: true}, {Severity: Medium}, {Severity: Info}}}
	by, sup := r.Counts()
	if sup != 1 || by[Medium] != 1 || by[High] != 0 {
		t.Errorf("counts = %v %d", by, sup)
	}
	if r.FailsAt(High) || !r.FailsAt(Medium) || !r.FailsAt(Low) {
		t.Error("FailsAt")
	}
}

func TestPipelineNotes(t *testing.T) {
	p := &Pipeline{File: "ci.yml"}
	p.AddNote(Pos{Line: 3}, "x %d", 1)
	p.AddNote(Pos{File: "inc.yml", Line: 1}, "y")
	if p.Notes[0].File != "ci.yml" || p.Notes[0].Message != "x 1" || p.Notes[1].File != "inc.yml" {
		t.Errorf("notes = %+v", p.Notes)
	}
	s := &Step{With: []Input{{Name: "Exit-Code", Value: Value{Raw: "0"}}}}
	if v, ok := s.Input("exit-code"); !ok || v.Raw != "0" {
		t.Error("Input")
	}
}
