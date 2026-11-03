package report

import (
	"encoding/json"
	"io"

	"github.com/codewithQasimAli/gatelint/internal/model"
	"github.com/codewithQasimAli/gatelint/internal/rules"
)

// SARIF 2.1.0 types. Only the properties gatelint emits are modelled.

// SarifLog is the top-level SARIF object.
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun is one analysis run.
type SarifRun struct {
	Tool        SarifTool         `json:"tool"`
	Invocations []SarifInvocation `json:"invocations"`
	Results     []SarifResult     `json:"results"`
	// OriginalURIBaseIDs documents the %SRCROOT% base.
	OriginalURIBaseIDs map[string]SarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
}

// SarifTool describes the analysis tool.
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

// SarifDriver is the tool component.
type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	SemanticVer    string      `json:"semanticVersion,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

// SarifMessage is a text message.
type SarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SarifRule is a reporting descriptor.
type SarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     SarifMessage       `json:"shortDescription"`
	FullDescription      SarifMessage       `json:"fullDescription"`
	Help                 SarifMessage       `json:"help"`
	HelpURI              string             `json:"helpUri"`
	DefaultConfiguration SarifConfiguration `json:"defaultConfiguration"`
	Properties           SarifRuleProps     `json:"properties"`
}

// SarifConfiguration holds the default level of a rule.
type SarifConfiguration struct {
	Level string `json:"level"`
}

// SarifRuleProps are rule properties understood by code scanning.
type SarifRuleProps struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity"`
}

// SarifResult is one finding.
type SarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             SarifMessage       `json:"message"`
	Locations           []SarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []SarifSuppression `json:"suppressions,omitempty"`
	Properties          SarifResultProps   `json:"properties"`
}

// SarifResultProps carries gatelint-specific details.
type SarifResultProps struct {
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Scanner     string   `json:"scanner,omitempty"`
	Job         string   `json:"job,omitempty"`
	Step        string   `json:"step,omitempty"`
	Conditional bool     `json:"conditional,omitempty"`
	Fix         string   `json:"fix"`
	Notes       []string `json:"notes,omitempty"`
}

// SarifSuppression marks an in-source suppression.
type SarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// SarifLocation is a result location.
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

// SarifPhysicalLocation is a file region.
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

// SarifArtifactLocation is a file reference.
type SarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SarifRegion is a line and column.
type SarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// SarifInvocation reports whether the run succeeded.
type SarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []SarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// SarifNotification is a note or error about the run.
type SarifNotification struct {
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations,omitempty"`
}

// SarifLevel maps a severity to a SARIF level.
func SarifLevel(s model.Severity) string {
	switch s {
	case model.High:
		return "error"
	case model.Medium:
		return "warning"
	}
	return "note"
}

func securitySeverity(s model.Severity) string {
	switch s {
	case model.High:
		return "8.0"
	case model.Medium:
		return "5.5"
	case model.Low:
		return "3.0"
	}
	return "1.0"
}

// BuildSARIF converts a result into a SARIF log.
func BuildSARIF(res *model.Result, version string) SarifLog {
	all := rules.All()
	index := map[string]int{}
	driver := SarifDriver{
		Name:           "gatelint",
		InformationURI: "https://github.com/codewithQasimAli/gatelint",
		Rules:          []SarifRule{},
	}
	if version != "" {
		driver.Version = version
	}
	for i, r := range all {
		index[r.ID] = i
		help := r.Explanation + "\n\nFix: " + r.Hint
		md := r.Explanation + "\n\n**Before**\n\n```yaml\n" + r.Before + "\n```\n\n**After**\n\n```yaml\n" + r.After + "\n```"
		driver.Rules = append(driver.Rules, SarifRule{
			ID:                   r.ID,
			Name:                 ruleName(r.Title),
			ShortDescription:     SarifMessage{Text: r.Title},
			FullDescription:      SarifMessage{Text: r.Explanation},
			Help:                 SarifMessage{Text: help, Markdown: md},
			HelpURI:              r.HelpURI(),
			DefaultConfiguration: SarifConfiguration{Level: SarifLevel(r.Severity)},
			Properties:           SarifRuleProps{Tags: []string{"security", "ci"}, Precision: "high", SecuritySeverity: securitySeverity(r.Severity)},
		})
	}
	run := SarifRun{
		Tool:               SarifTool{Driver: driver},
		Results:            []SarifResult{},
		OriginalURIBaseIDs: map[string]SarifArtifactLocation{"%SRCROOT%": {URI: "./"}},
	}
	for _, f := range res.Findings {
		r := SarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           index[f.RuleID],
			Level:               SarifLevel(f.Severity),
			Message:             SarifMessage{Text: f.Message},
			Locations:           []SarifLocation{location(f.File, f.Line, f.Column)},
			PartialFingerprints: map[string]string{"gatelintFingerprint/v1": f.Fingerprint},
			Properties: SarifResultProps{
				Severity: f.Severity.String(), Confidence: string(f.Confidence), Scanner: f.Tool,
				Job: f.Job, Step: f.Step, Conditional: f.Conditional, Fix: f.Hint, Notes: f.Notes,
			},
		}
		if f.Suppressed {
			r.Suppressions = []SarifSuppression{{Kind: "inSource", Justification: f.SuppressionReason}}
		}
		run.Results = append(run.Results, r)
	}
	inv := SarifInvocation{ExecutionSuccessful: len(res.Errors) == 0}
	for _, e := range res.Errors {
		inv.Notifications = append(inv.Notifications, SarifNotification{Level: "error", Message: SarifMessage{Text: e.Message},
			Locations: []SarifLocation{location(e.File, 0, 0)}})
	}
	for _, n := range res.Notes {
		inv.Notifications = append(inv.Notifications, SarifNotification{Level: "note", Message: SarifMessage{Text: n.Message},
			Locations: []SarifLocation{location(n.File, n.Line, 0)}})
	}
	run.Invocations = []SarifInvocation{inv}
	return SarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []SarifRun{run},
	}
}

func location(file string, line, col int) SarifLocation {
	if line < 1 {
		line = 1
	}
	return SarifLocation{PhysicalLocation: SarifPhysicalLocation{
		ArtifactLocation: SarifArtifactLocation{URI: file, URIBaseID: "%SRCROOT%"},
		Region:           SarifRegion{StartLine: line, StartColumn: col},
	}}
}

// ruleName converts a title into a PascalCase identifier.
func ruleName(title string) string {
	var out []rune
	upper := true
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z':
			if upper {
				r -= 'a' - 'A'
			}
			out = append(out, r)
			upper = false
		case r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			out = append(out, r)
			upper = false
		default:
			upper = true
		}
	}
	return string(out)
}

// SARIF writes a SARIF 2.1.0 log.
func SARIF(w io.Writer, res *model.Result, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(BuildSARIF(res, opts.Version))
}
