package report

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/konveyor/analyzer-lsp/hubapi"
)

func CompareRuleset(want, got hubapi.RuleSet) Result {
	r := Result{}
	// compare tags
	result := CompareTags(want.Tags, got.Tags)
	r.P = append(r.P, result.P...)
	r.F = append(r.F, result.F...)

	var total int
	// compare incidents
	for wantRuleId, wantViolation := range want.Violations {
		total += 1
		if gotViolation, ok := got.Violations[wantRuleId]; ok {
			result := CompareViolation(wantViolation, gotViolation)
			if len(result.F) == 0 && len(result.W) == 0 {
				r.Pass(fmt.Sprintf("rule %s matched", wantRuleId), &result)
			} else if len(result.W) != 0 {
				r.Warn(fmt.Sprintf("rule %s matched with differences", wantRuleId), &result)
			} else {
				r.Fail(fmt.Sprintf("rule %s did not match", wantRuleId), &result)
			}
			delete(got.Violations, wantRuleId)
		} else {
			r.Fail(fmt.Sprintf("%s violation not found", wantRuleId), nil)
		}
	}
	for gotRuleId := range got.Violations {
		r.Warn(fmt.Sprintf("unwanted rule %s matched", gotRuleId), nil)
	}
	return r
}

func CompareViolation(want, got hubapi.Violation) Result {
	r := Result{}
	if reflect.DeepEqual(got.Category, want.Category) {
		r.Pass(fmt.Sprintf("category matched '%s'", *got.Category), nil)
	} else {
		r.Fail(fmt.Sprintf("got cat '%v', want '%v'", got.Category, want.Category), nil)
	}
	if reflect.DeepEqual(got.Effort, want.Effort) {
		r.Pass(fmt.Sprintf("effort matched '%d'", *got.Effort), nil)
	} else {
		r.Fail(fmt.Sprintf("got effort '%v', want '%v'", got.Effort, want.Effort), nil)
	}
	result := CompareIncidents(want.Incidents, got.Incidents)
	if len(result.F) == 0 && len(result.W) == 0 {
		r.Pass(fmt.Sprintf("%d incidents matched", len(got.Incidents)), &result)
	} else if len(result.W) == 0 {
		r.Fail(fmt.Sprintf("%d incidents didn't match", len(got.Incidents)), &result)
	} else {
		r.Warn("incidents matched with differences", &result)
	}
	return r
}

func CompareIncidents(want, got []hubapi.Incident) Result {
	r := Result{}
	for fileName, wantIncidents := range groupByFilenames(want) {
		gotIncidents := findIncidentByFilename(fileName, got)
		if len(gotIncidents) == 0 {
			r.Fail(fmt.Sprintf("%d incidents not found in %s", len(wantIncidents), fileName), nil)
		} else if len(gotIncidents) != len(wantIncidents) {
			r.Warn(fmt.Sprintf("%d incidents found, want %d", len(gotIncidents), len(wantIncidents)), nil)
		} else {
			r.Pass(fmt.Sprintf("%d incidents found in %s", len(gotIncidents), fileName), nil)
		}
	}

	for gotFilename, gotIncidents := range groupByFilenames(got) {
		if len(findIncidentByFilename(gotFilename, want)) == 0 {
			r.Warn(fmt.Sprintf("unwanted %d incidents found in %s", len(gotIncidents), gotFilename), nil)
		}
	}
	return r
}

func CompareTags(want, got []string) Result {
	r := Result{}
	gotDedup := map[string]bool{}
	for _, gotTag := range got {
		if _, ok := gotDedup[gotTag]; !ok {
			gotDedup[gotTag] = true
		}
	}
	for _, wantTag := range want {
		if _, ok := gotDedup[wantTag]; !ok {
			r.Fail(fmt.Sprintf("tag '%s' not found", wantTag), nil)
		} else {
			r.Pass(fmt.Sprintf("tag '%s' found", wantTag), nil)
		}
	}
	for _, gotTag := range got {
		if _, ok := gotDedup[gotTag]; !ok {
			r.Warn(fmt.Sprintf("unwanted tag '%s' found", gotTag), nil)
		}
	}
	return r
}

func findIncidentByFilename(fileName string, inList []hubapi.Incident) (matches []hubapi.Incident) {
	for _, want := range inList {
		if strings.Contains(string(want.URI), fileName) {
			matches = append(matches, want)
		}
	}
	return
}

func groupByFilenames(list []hubapi.Incident) map[string][]hubapi.Incident {
	group := map[string][]hubapi.Incident{}
	for _, incident := range list {
		fileName := strings.TrimPrefix(string(incident.URI), "contents/")
		fileName = strings.TrimPrefix(fileName, "file:///")
		fileName = strings.TrimPrefix(fileName, "jdt://")
		if _, ok := group[fileName]; !ok {
			group[fileName] = make([]hubapi.Incident, 0)
		}
		group[fileName] = append(group[fileName], incident)
	}
	return group
}

type output struct {
	msg       string
	subResult *Result
}

type Result struct {
	P []output
	W []output
	F []output
}

func appendTo(to []output, m string, s *Result) (arr []output) {
	return append(to, output{
		msg:       m,
		subResult: s,
	})
}

func (r *Result) Pass(m string, s *Result) {
	r.P = appendTo(r.P, m, s)
}

func (r *Result) Fail(m string, s *Result) {
	r.F = appendTo(r.F, m, s)
}

func (r *Result) Warn(m string, s *Result) {
	r.W = appendTo(r.W, m, s)
}

func (r *Result) String() string {
	res := []string{}
	appendToRes := func(res []string, marker string, from []output) []string {
		for _, f := range from {
			res = append(res, fmt.Sprintf("%s %s", marker, f.msg))
			if f.subResult != nil {
				res = append(res, fmt.Sprintf("\t%s",
					strings.ReplaceAll(f.subResult.String(), "\n", "\n\t")))
			}
		}
		return res
	}
	res = appendToRes(res, "✅", r.P)
	res = appendToRes(res, "⚠️", r.W)
	res = appendToRes(res, "❌", r.F)
	return strings.Join(res, "\n")
}
