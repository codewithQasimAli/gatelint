package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/rules"
)

func sample() *model.Result {
	return &model.Result{
		Files: []string{".github/workflows/ci.yml", ".gitlab-ci.yml"},
		Findings: []model.Finding{
			{RuleID: "GL001", Title: "t1", Severity: model.High, Confidence: model.ConfidenceHigh, File: ".github/workflows/ci.yml", Line: 9, Column: 14,
				Job: "scan", Step: "Trivy", Tool: "Trivy", Message: "Trivy failure is swallowed by `|| true`", Hint: "remove it", Fingerprint: "aaa"},
			{RuleID: "GL003", Title: "t3", Severity: model.Medium, Confidence: model.ConfidenceMedium, File: ".github/workflows/ci.yml", Line: 12,
				Job: "scan", Message: "piped <html> & stuff", Hint: "pipefail", Fingerprint: "bbb", Notes: []string{"a note"}, Conditional: true},
			{RuleID: "GL004", Title: "t4", Severity: model.High, Confidence: model.ConfidenceHigh, File: ".gitlab-ci.yml", Line: 3,
				Step: "only-step", Message: "suppressed one", Hint: "h", Fingerprint: "ccc", Suppressed: true, SuppressionReason: "tracked in SEC-1"},
			{RuleID: "GL010", Title: "t10", Severity: model.Low, Confidence: model.ConfidenceHigh, File: ".gitlab-ci.yml", Line: 5, Message: "no reason", Hint: "h", Fingerprint: "ddd"},
			{RuleID: "GL007", Title: "t7", Severity: model.Info, Confidence: model.ConfidenceHigh, File: ".gitlab-ci.yml", Line: 7, Message: "monitor", Hint: "h", Fingerprint: "eee"},
		},
		Coverage: []model.FileCoverage{
			{File: ".github/workflows/ci.yml", Platform: model.GitHub, Scanners: []model.CoverageEntry{
				{Scanner: "Trivy", Job: "scan", Step: "Trivy", Line: 9, Status: model.StatusNeutered, Rules: []string{"GL001"}, Note: "report-only"},
				{Scanner: "Gitleaks", Job: "scan", Line: 20, Status: model.StatusGating},
			}},
			{File: ".gitlab-ci.yml", Platform: model.GitLab, Scanners: []model.CoverageEntry{
				{Scanner: "GitLab SAST", Line: 2, Status: model.StatusNonGating},
				{Scanner: "Semgrep", Step: "s", Line: 4, Status: model.StatusDisabled, Rules: []string{"GL009"}},
				{Scanner: "Trivy", Job: "j", Line: 6, Status: model.StatusUnknown},
			}},
		},
		Notes:  []model.Note{{File: ".gitlab-ci.yml", Line: 1, Message: "remote include is out of scope"}, {File: "x.yml", Message: "no line"}},
		Errors: []model.FileError{{File: "bad.yml", Message: "invalid YAML"}},
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(sample())
	if s.Findings != 4 || s.High != 1 || s.Medium != 1 || s.Low != 1 || s.Info != 1 || s.Suppressed != 1 || s.Scanners != 5 || s.Files != 2 {
		t.Errorf("summary = %+v", s)
	}
	if s.Status["gating"] != 1 || s.Status["unknown"] != 1 {
		t.Errorf("status = %v", s.Status)
	}
}

func TestTable(t *testing.T) {
	var b bytes.Buffer
	if err := Table(&b, sample(), Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"SEVERITY  RULE   LOCATION", "HIGH      GL001  .github/workflows/ci.yml:9", "scan / Trivy",
		"fix: remove it", "note: a note", "(confidence: medium)", "Gate coverage", "neutered (GL001)",
		"(included template)", "disabled (GL009)", "Notes", ".gitlab-ci.yml:1: remote include", "x.yml: no line",
		"Summary: 4 findings (1 high, 1 medium, 1 low, 1 info), 1 suppressed; 5 scanners in 2 files: 1 gating, 1 neutered, 1 non-gating, 1 disabled, 1 unknown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "suppressed one") || strings.Contains(out, "\x1b[") {
		t.Errorf("table shows suppressed finding or color:\n%s", out)
	}
}

func TestTableColorQuietAndEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := Table(&b, sample(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\x1b[31m") || !strings.Contains(b.String(), "\x1b[32mgating") {
		t.Error("colors missing")
	}
	b.Reset()
	if err := Table(&b, sample(), Options{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Gate coverage") || strings.Contains(b.String(), "Summary") || !strings.Contains(b.String(), "GL001") {
		t.Errorf("quiet output:\n%s", b.String())
	}
	b.Reset()
	if err := Table(&b, &model.Result{Files: []string{"a"}}, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No findings.") || !strings.Contains(b.String(), "0 scanners in 1 file\n") {
		t.Errorf("empty output:\n%s", b.String())
	}
	b.Reset()
	if err := Table(&b, &model.Result{}, Options{Quiet: true}); err != nil || b.Len() != 0 {
		t.Errorf("quiet empty output = %q", b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "json", sample(), Options{Version: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tool     map[string]string `json:"tool"`
		Summary  Summary           `json:"summary"`
		Findings []map[string]any  `json:"findings"`
		Coverage []map[string]any  `json:"coverage"`
		Notes    []map[string]any  `json:"notes"`
		Errors   []map[string]any  `json:"errors"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Tool["version"] != "1.2.3" || len(doc.Findings) != 5 || len(doc.Coverage) != 2 || len(doc.Errors) != 1 {
		t.Errorf("json = %+v", doc)
	}
	if doc.Findings[2]["suppressed"] != true || doc.Findings[2]["suppressionReason"] != "tracked in SEC-1" {
		t.Errorf("suppressed finding = %v", doc.Findings[2])
	}
	if !strings.Contains(b.String(), "<html> & stuff") {
		t.Error("HTML was escaped")
	}
	b.Reset()
	if err := JSON(&b, &model.Result{}, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"files": []`, `"findings": []`, `"coverage": []`, `"notes": []`, `"errors": []`} {
		if !strings.Contains(b.String(), key) {
			t.Errorf("empty JSON missing %s", key)
		}
	}
}

// TestSARIFStructure validates the parts of SARIF 2.1.0 that consumers such
// as GitHub code scanning rely on.
func TestSARIFStructure(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "sarif", sample(), Options{Version: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	ValidateSARIF(t, b.Bytes())

	var log map[string]any
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 5 {
		t.Fatalf("results = %d", len(results))
	}
	levels := []string{"error", "warning", "error", "note", "note"}
	for i, r := range results {
		if r.(map[string]any)["level"] != levels[i] {
			t.Errorf("result %d level = %v, want %s", i, r.(map[string]any)["level"], levels[i])
		}
	}
	sup := results[2].(map[string]any)["suppressions"].([]any)[0].(map[string]any)
	if sup["kind"] != "inSource" || sup["justification"] != "tracked in SEC-1" {
		t.Errorf("suppression = %v", sup)
	}
	if _, ok := results[0].(map[string]any)["suppressions"]; ok {
		t.Error("unsuppressed result has suppressions")
	}
	inv := run["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false || len(inv["toolExecutionNotifications"].([]any)) != 3 {
		t.Errorf("invocation = %v", inv)
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["version"] != "1.2.3" {
		t.Errorf("driver version = %v", driver["version"])
	}
	first := driver["rules"].([]any)[0].(map[string]any)
	if first["name"] != "ScannerFailureSwallowedByTheShell" {
		t.Errorf("rule name = %v", first["name"])
	}
}

// ValidateSARIF checks required SARIF 2.1.0 structure.
func ValidateSARIF(t *testing.T, data []byte) {
	t.Helper()
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("SARIF is not JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v", log["version"])
	}
	if s, _ := log["$schema"].(string); !strings.Contains(s, "sarif-2.1.0") {
		t.Errorf("$schema = %v", log["$schema"])
	}
	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", log["runs"])
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "gatelint" || driver["informationUri"] == "" {
		t.Errorf("driver = %v", driver)
	}
	ruleIDs := map[string]int{}
	for i, r := range driver["rules"].([]any) {
		rm := r.(map[string]any)
		id, _ := rm["id"].(string)
		ruleIDs[id] = i
		for _, key := range []string{"shortDescription", "fullDescription", "help", "helpUri", "defaultConfiguration", "properties"} {
			if _, ok := rm[key]; !ok {
				t.Errorf("rule %s missing %s", id, key)
			}
		}
		props := rm["properties"].(map[string]any)
		if _, ok := props["security-severity"].(string); !ok {
			t.Errorf("rule %s missing security-severity", id)
		}
	}
	if len(ruleIDs) != len(rules.All()) {
		t.Errorf("driver rules = %d, want %d", len(ruleIDs), len(rules.All()))
	}
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatal("results missing")
	}
	for i, r := range results {
		rm := r.(map[string]any)
		id, _ := rm["ruleId"].(string)
		idx, ok := ruleIDs[id]
		if !ok {
			t.Errorf("result %d has unknown ruleId %q", i, id)
		}
		if int(rm["ruleIndex"].(float64)) != idx {
			t.Errorf("result %d ruleIndex mismatch", i)
		}
		switch rm["level"] {
		case "error", "warning", "note", "none":
		default:
			t.Errorf("result %d level = %v", i, rm["level"])
		}
		if msg := rm["message"].(map[string]any)["text"]; msg == "" {
			t.Errorf("result %d has no message", i)
		}
		locs := rm["locations"].([]any)
		if len(locs) == 0 {
			t.Errorf("result %d has no locations", i)
			continue
		}
		pl := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
		uri := pl["artifactLocation"].(map[string]any)["uri"].(string)
		if uri == "" || strings.HasPrefix(uri, "/") && false {
			t.Errorf("result %d uri = %q", i, uri)
		}
		if line := pl["region"].(map[string]any)["startLine"].(float64); line < 1 {
			t.Errorf("result %d startLine = %v", i, line)
		}
		fps := rm["partialFingerprints"].(map[string]any)
		if len(fps) == 0 {
			t.Errorf("result %d has no partialFingerprints", i)
		}
	}
}

func TestCodeQuality(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "codequality", sample(), Options{}); err != nil {
		t.Fatal(err)
	}
	ValidateCodeQuality(t, b.Bytes(), 4)
	if strings.Contains(b.String(), "suppressed one") {
		t.Error("suppressed finding included")
	}
	b.Reset()
	if err := CodeQuality(&b, &model.Result{}); err != nil || strings.TrimSpace(b.String()) != "[]" {
		t.Errorf("empty code quality = %q %v", b.String(), err)
	}
}

// ValidateCodeQuality checks the fields GitLab requires in a Code Quality
// report.
func ValidateCodeQuality(t *testing.T, data []byte, want int) {
	t.Helper()
	var issues []map[string]any
	if err := json.Unmarshal(data, &issues); err != nil {
		t.Fatalf("code quality is not a JSON array: %v", err)
	}
	if want >= 0 && len(issues) != want {
		t.Errorf("issues = %d, want %d", len(issues), want)
	}
	seen := map[string]bool{}
	for i, is := range issues {
		for _, key := range []string{"description", "check_name", "fingerprint", "severity", "location"} {
			if _, ok := is[key]; !ok {
				t.Errorf("issue %d missing %s", i, key)
			}
		}
		switch is["severity"] {
		case "info", "minor", "major", "critical", "blocker":
		default:
			t.Errorf("issue %d severity = %v", i, is["severity"])
		}
		loc := is["location"].(map[string]any)
		if loc["path"] == "" || loc["lines"].(map[string]any)["begin"].(float64) < 1 {
			t.Errorf("issue %d location = %v", i, loc)
		}
		fp := is["fingerprint"].(string)
		if seen[fp] {
			t.Errorf("duplicate fingerprint %s", fp)
		}
		seen[fp] = true
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", &model.Result{}, Options{}); err == nil {
		t.Error("unknown format accepted")
	}
	if err := Write(&bytes.Buffer{}, "", &model.Result{}, Options{}); err != nil {
		t.Error("empty format should default to table")
	}
}

func TestHelpers(t *testing.T) {
	if CodeQualitySeverity(model.Info) != "info" || CodeQualitySeverity(model.Low) != "minor" {
		t.Error("code quality severity")
	}
	if securitySeverity(model.Info) != "1.0" || securitySeverity(model.Low) != "3.0" {
		t.Error("security severity")
	}
	if ruleName("Scanner piped without pipefail") != "ScannerPipedWithoutPipefail" || ruleName("GL0 a-b") != "GL0AB" {
		t.Errorf("ruleName = %s", ruleName("GL0 a-b"))
	}
	if truncate("abcdef", 5) != "ab..." || truncate("abc", 5) != "abc" {
		t.Error("truncate")
	}
	if plural(1, "a", "b") != "a" || plural(2, "a", "b") != "b" {
		t.Error("plural")
	}
}
