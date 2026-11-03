package rules

import (
	"sort"
	"strings"

	"github.com/codewithQasimAli/gatelint/internal/model"
)

const templateNote = "GitLab security templates do not fail pipelines on findings; enforce results with merge request approval policies"

// Coverage builds the gate coverage summary: every scanner use with its
// status, grouped by file in the order given.
func Coverage(ctx *Context, findings []model.Finding, files []string) []model.FileCoverage {
	byUse := map[int][]model.Finding{}
	for _, f := range findings {
		if f.UseID >= 0 {
			byUse[f.UseID] = append(byUse[f.UseID], f)
		}
	}
	byFile := map[string][]model.CoverageEntry{}
	platform := map[string]model.Platform{}
	for _, u := range ctx.Uses {
		e := entry(ctx, u, byUse[u.ID])
		byFile[u.Pos.File] = append(byFile[u.Pos.File], e)
		platform[u.Pos.File] = u.Pipeline.Platform
	}
	var out []model.FileCoverage
	seen := map[string]bool{}
	add := func(file string) {
		if seen[file] || len(byFile[file]) == 0 {
			return
		}
		seen[file] = true
		entries := byFile[file]
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Line < entries[j].Line })
		out = append(out, model.FileCoverage{File: file, Platform: platform[file], Scanners: entries})
	}
	for _, f := range files {
		add(f)
	}
	rest := make([]string, 0, len(byFile))
	for f := range byFile {
		rest = append(rest, f)
	}
	sort.Strings(rest)
	for _, f := range rest {
		add(f)
	}
	return out
}

func entry(ctx *Context, u *Use, fs []model.Finding) model.CoverageEntry {
	e := model.CoverageEntry{Scanner: u.Name(), Job: u.JobName(), Step: u.StepName(), Line: u.Pos.Line}
	ruleSet := map[string]bool{}
	nonGating := false
	for _, f := range fs {
		switch {
		case f.RuleID == "GL009":
			ruleSet[f.RuleID] = true
		case f.RuleID == "GL007":
			nonGating = true
		case neutering[f.RuleID]:
			ruleSet[f.RuleID] = true
		}
	}
	var ids []string
	for id := range ruleSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	e.Rules = ids
	switch {
	case u.Disabled:
		e.Status = model.StatusDisabled
		e.Rules = []string{"GL009"}
	case len(ids) > 0:
		e.Status = model.StatusNeutered
		e.Note = ctx.mitigations[u.ID]
	case u.Template != nil:
		e.Status = model.StatusNonGating
		e.Note = templateNote
	case nonGating || u.infoOnly():
		e.Status = model.StatusNonGating
		if u.Eval != nil {
			e.Note = u.Eval.Note
		}
		if nonGating {
			e.Rules = []string{"GL007"}
		}
	case u.Eval != nil && u.Eval.Indeterminate():
		e.Status = model.StatusUnknown
		e.Note = indeterminateNote(u)
	default:
		e.Status = model.StatusGating
	}
	return e
}

func indeterminateNote(u *Use) string {
	ev := u.Eval
	if ev.ConfigFile != "" {
		return "gating depends on the configuration file " + ev.ConfigFile
	}
	var names []string
	for _, h := range ev.Unknown {
		v := h.Name
		if h.Value != "" {
			v += " " + h.Value
		}
		names = append(names, v)
	}
	return "gating depends on a value gatelint cannot resolve: " + strings.Join(names, ", ")
}
