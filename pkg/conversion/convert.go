package conversion

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"github.com/konveyor/analyzer-lsp/hubapi"
	"gopkg.in/yaml.v2"
)

type analyzerRules struct {
	rules    []map[string]interface{}
	metadata windup.Metadata
}

func ConvertWindupRulesetsToAnalyzer(windups []windup.Ruleset, baseLocation, outputDir string) (map[string]*analyzerRules, error) {
	outputRulesets := map[string]*analyzerRules{}
	for idx, windupRuleset := range windups {
		ruleset := ConvertWindupRulesetToAnalyzer(windupRuleset)
		rulesetRelativePath := strings.Trim(strings.Replace(strings.Replace(windupRuleset.SourceFile, baseLocation, "", 1), filepath.Base(windupRuleset.SourceFile), "", 1), "/")
		rulesetFileName := strings.Replace(filepath.Base(windupRuleset.SourceFile), ".xml", ".yaml", 1)
		yamlPath := filepath.Join(outputDir, rulesetRelativePath, fmt.Sprintf("%.02d-%s", idx+1, strings.Replace(rulesetFileName, ".windup.yaml", "", 1)), rulesetFileName)
		if reflect.DeepEqual(ruleset, map[string]interface{}{}) {
			continue
		}
		if _, ok := outputRulesets[yamlPath]; !ok {
			outputRulesets[yamlPath] = &analyzerRules{
				rules:    []map[string]interface{}{},
				metadata: windupRuleset.Metadata,
			}
		}
		outputRulesets[yamlPath].rules = append(outputRulesets[yamlPath].rules, ruleset...)
		outputRulesets[yamlPath].metadata = windupRuleset.Metadata
	}
	for path, ruleset := range outputRulesets {
		dirName := filepath.Dir(path)
		err := os.MkdirAll(dirName, 0777)
		if err != nil {
			fmt.Printf("Skipping because of an error creating %s: %s\n", path, err.Error())
			continue
		}
		analyzerRuleset := hubapi.RuleSet{
			Name:        strings.Replace(filepath.Base(path), ".windup.yaml", "", 1),
			Description: string(ruleset.metadata.Description),
			Labels:      ruleset.metadata.Tag,
		}
		rulesetGoldenFilePath := filepath.Join(dirName, "ruleset.yaml")
		err = writeYAML(analyzerRuleset, rulesetGoldenFilePath)
		if err != nil {
			fmt.Printf("Skipping because of an error writing ruleset golden file to %s: %s\n", rulesetGoldenFilePath, err.Error())
			continue
		}
		err = writeYAML(ruleset.rules, path)
		if err != nil {
			fmt.Printf("Skipping because of an error writing to %s: %s\n", path, err.Error())
			continue
		}
	}
	return outputRulesets, nil
}

func ConvertWindupRulesetToAnalyzer(ruleset windup.Ruleset) []map[string]interface{} {
	// TODO Ruleset.Metadata
	// TODO Ruleset.PackageMapping
	// TODO Ruleset.Filemapping
	// TODO Ruleset.Javaclassignore
	rules := []map[string]interface{}{}
	// we need unique rule id's within a ruleset
	uniqueIds := map[string]int{}
	for _, windupRule := range ruleset.Rules.Rule {
		ruleId := windupRule.Id
		if val, found := uniqueIds[ruleId]; found {
			ruleId = fmt.Sprintf("%s-%.02d", ruleId, val)
			uniqueIds[ruleId] += 1
		} else {
			uniqueIds[ruleId] = 1
		}
		// formatted, _ := yaml.Marshal(windupRule)
		// fmt.Println(string(formatted))
		rule := map[string]interface{}{
			"ruleID": ruleId,
		}

		where := flattenWhere(windupRule.Where)
		if !reflect.DeepEqual(windupRule.When, windup.When{}) {
			when, customVars := convertWindupWhenToAnalyzer(windupRule.When, where)
			if len(when) == 1 {
				rule["when"] = when[0]
			} else if len(when) > 1 {
				rule["when"] = map[string]interface{}{"or": when}
			} else {
				continue
			}
			rule["customVariables"] = customVars
		} else {
			continue
		}

		// TODO Rule.Perform
		if !reflect.DeepEqual(windupRule.Perform, windup.Iteration{}) {
			perform := convertWindupPerformToAnalyzer(windupRule.Perform, where)
			// TODO only support a single action in perform right now, default to hint
			tags, ok := perform["tag"].([]string)
			if !ok {
				tags = nil
			}
			if perform["message"] != nil {
				rule["message"] = perform["message"]
			} else if len(tags) != 0 {
				rule["tag"] = tags
			} else {
				fmt.Println("\n\nNo action parsed\n\n")
				continue
			}
			// for k, v := range perform {
			// 	rule[k] = v
			// }
		} else {
			continue
		}

		// TODO - Iteration
		// TODO Rule.Otherwise
		rules = append(rules, rule)
	}
	return rules
}

func convertWindupWhenToAnalyzer(windupWhen windup.When, where map[string]string) ([]map[string]interface{}, []map[string]interface{}) {
	//
	// TODO Rule.When
	// TODO - Graphquery
	conditions := []map[string]interface{}{}
	var customVars []map[string]interface{}
	if windupWhen.Graphquery != nil {
		for _, gq := range windupWhen.Graphquery {
			// JarArchiveModel is a special case for deps
			// that are actually included in a lib folder as jars
			if gq.Discriminator == "JarArchiveModel" {
				conditions = append(conditions, convertWindupGraphQueryJarArchiveModel(gq))
			} else if gq.Discriminator == "TechnologyTagModel" {
				conditions = append(conditions, map[string]interface{}{"builtin.hasTags": []string{gq.Property.Value}})
			}
		}
	}
	if windupWhen.Project != nil {
		for _, pc := range windupWhen.Project {
			conditions = append(conditions, map[string]interface{}{"java.dependency": convertWindupDependencyToAnalyzer(pc.Artifact)})
		}
	}
	if windupWhen.Dependency != nil {
		for _, dc := range windupWhen.Dependency {
			conditions = append(conditions, map[string]interface{}{"java.dependency": convertWindupDependencyToAnalyzer(dc)})
		}
	}
	if windupWhen.And != nil {
		whens := []map[string]interface{}{}
		for _, condition := range windupWhen.And {
			converted, _ := convertWindupWhenToAnalyzer(condition, where)
			for _, c := range converted {
				whens = append(whens, c)
			}
		}
		conditions = append(conditions, map[string]interface{}{"and": whens})
	}
	if windupWhen.Or != nil {
		whens := []map[string]interface{}{}
		for _, condition := range windupWhen.Or {
			converted, _ := convertWindupWhenToAnalyzer(condition, where)
			for _, c := range converted {
				whens = append(whens, c)
			}
		}
		conditions = append(conditions, map[string]interface{}{"or": whens})
	}
	if windupWhen.Not != nil {
		for _, condition := range windupWhen.Not {
			converted, _ := convertWindupWhenToAnalyzer(condition, where)
			for _, c := range converted {
				c["not"] = true
				conditions = append(conditions, c)
			}
		}
	}
	if windupWhen.Filecontent != nil {
		for _, fc := range windupWhen.Filecontent {
			condition := map[string]interface{}{
				"builtin.filecontent": strings.Replace(substituteWhere(where, fc.Pattern), "{*}", "*", -1),
			}
			if fc.As != "" {
				condition["as"] = fc.As
			}
			if fc.From != "" {
				condition["from"] = fc.From
			}
			conditions = append(conditions, condition)
		}
	}
	if windupWhen.Javaclass != nil {
		for _, jc := range windupWhen.Javaclass {
			customVars = convertWhereToCustomVars(where, jc.References)
			pattern := strings.Replace(substituteWhere(where, jc.References), "{*}", "*", -1)
			pattern = strings.Replace(pattern, "(*)", "*", -1)
			pattern = strings.Replace(pattern, ".*", "*", -1)
			pattern = strings.Replace(pattern, `\`, "", -1)
			// Make some .* regesx's more generic.
			pattern = strings.Replace(pattern, `(.*)?.`, ".*", -1)
			pattern = strings.Replace(pattern, `.[^.]+`, "*", -1)
			pattern = strings.Replace(pattern, `[^.]+`, "*", -1)
			pattern = strings.Replace(pattern, `(.[^.]*)*`, "*", -1)
			pattern = strings.Replace(pattern, `+[^.]*?`, "*", -1)
			if jc.Location != nil {
				for _, location := range jc.Location {
					condition := map[string]interface{}{
						"java.referenced": map[string]interface{}{
							"location": location,
							"pattern":  pattern,
							// TODO handle jc.Annotationtype
							// TODO handle jc.Annotationlist
							// TODO handle jc.Annotationliteral
							// TODO handle jc.MatchesSource
							// TODO handle jc.In
						},
					}
					if jc.As != "" {
						condition["as"] = jc.As
						// TODO (shurley): Only set when something is going to use this as block
						// condition["ignore"] = true
					}
					if jc.From != "" {
						condition["from"] = jc.From
					}

					conditions = append(conditions, condition)
				}
			} else {
				condition := map[string]interface{}{
					"java.referenced": map[string]interface{}{
						"pattern": pattern,
						// TODO handle jc.Annotationtype
						// TODO handle jc.Annotationlist
						// TODO handle jc.Annotationliteral
						// TODO handle jc.MatchesSource
						// TODO handle jc.In
					},
				}
				if jc.As != "" {
					condition["as"] = jc.As
					// TODO (shurley): Only set when something is going to use this as block
					// condition["ignore"] = true
				}
				if jc.From != "" {
					condition["from"] = jc.From
				}
				conditions = append(conditions, condition)
			}
		}
	}
	if windupWhen.Xmlfile != nil {
		for _, xf := range windupWhen.Xmlfile {
			if xf.Matches == "" {
				// TODO handle systemid and publicid
				continue
			}
			matches := strings.Replace(xf.Matches, "windup:", "", -1)
			namespaces := map[string]string{}
			if xf.Namespace != nil {
				for _, ns := range xf.Namespace {
					namespaces[ns.Prefix] = ns.Uri
				}
			}
			xmlCond := map[string]interface{}{
				"xpath":      substituteWhere(where, matches),
				"namespaces": namespaces,
			}
			// TODO We don't support regexes here, may need to break it out into a separate lookup that gets passed through
			if xf.In != "" {
				in := substituteWhere(where, xf.In)
				if strings.Contains(in, "{*}") {
					conditions = append(conditions, map[string]interface{}{
						"builtin.file": strings.Replace(xf.In, "{*}", "*", -1),
						"as":           "xmlfiles",
						"ignore":       true,
					})
					xmlCond["from"] = "xmlfiles"
					xmlCond["filepaths"] = "{{xmlfiles.filepaths}}"
				} else if strings.Contains(in, "|") {
					filepaths := []string{}
					pieces := strings.Split(in, "|")
					for _, piece := range pieces {
						filepaths = append(filepaths, strings.Trim(piece, "()"))
					}
					xmlCond["filepaths"] = pieces
				} else {
					xmlCond["filepaths"] = []string{in}
				}
			}
			condition := map[string]interface{}{
				"builtin.xml": xmlCond,
			}
			if xf.As != "" {
				condition["as"] = xf.As
				// TODO this is probably a dumb assumption
				//	condition["ignore"] = true
			}
			// TODO What should we do if there's already a from because we had to split the task?
			if xf.From != "" {
				condition["from"] = xf.From
			}
			conditions = append(conditions, condition)
		}
	}

	if windupWhen.File != nil {
		for _, f := range windupWhen.File {
			condition := map[string]interface{}{
				"builtin.file": strings.Replace(substituteWhere(where, f.Filename), "{*}", "*", -1),
			}
			if f.As != "" {
				condition["as"] = f.As
				// TODO this is probably a dumb assumption
				//condition["ignore"] = true
			}
			if f.From != "" {
				condition["from"] = f.From
			}
			conditions = append(conditions, condition)
		}
	}
	if windupWhen.Fileexists != nil {
		for _, f := range windupWhen.Fileexists {
			condition := map[string]interface{}{
				"builtin.file": strings.Replace(substituteWhere(where, f.Filename), "{*}", "*", -1),
			}
			conditions = append(conditions, condition)
		}
	}
	// TODO below here

	// What is this ???
	if windupWhen.True != "" {
		// conditions = append(conditions, map[string]interface{}{"true": nil})
	}
	// What is this ???
	if windupWhen.False != "" {
		// conditions = append(conditions, map[string]interface{}{"false": nil})
	}
	// What is this ???
	if windupWhen.Iterablefilter != nil {
		// conditions = append(conditions, map[string]interface{}{"iterable-filter": nil})
	}
	// What is this ???
	if windupWhen.Tofilemodel != nil {
		// conditions = append(conditions, map[string]interface{}{"tofilemodel": nil})
	}
	// Test related
	if windupWhen.Classificationexists != nil {
		// conditions = append(conditions, map[string]interface{}{"classification-exists": nil})
	}
	// Test related
	if windupWhen.Hintexists != nil {
		// conditions = append(conditions, map[string]interface{}{"hint-exists": nil})
	}
	// Test related
	if windupWhen.Lineitemexists != nil {
		// conditions = append(conditions, map[string]interface{}{"lineitem-exists": nil})
	}
	// Test related
	if windupWhen.Technologystatisticsexists != nil {
		// conditions = append(conditions, map[string]interface{}{"technology-statistics-exists": nil})
	}
	// Test related
	if windupWhen.Technologytagexists != nil {
		// conditions = append(conditions, map[string]interface{}{"technology-tag-exists": nil})
	}
	return conditions, customVars
}

func convertWhereToCustomVars(whereMap map[string]string, fullPattern string) []map[string]interface{} {
	l := []map[string]interface{}{}
	newString := fullPattern
	for k, v := range whereMap {
		newString = strings.ReplaceAll(newString, "{"+k+"}.", fmt.Sprintf("(?P<%s>%s.)?", k, v))
		newString = strings.ReplaceAll(newString, "{"+k+"}", fmt.Sprintf("(?P<%s>%s)?", k, v))
		newString = strings.ReplaceAll(newString, "?+", "?")
		m := map[string]interface{}{
			"name":               k,
			"nameOfCaptureGroup": k,
		}
		l = append(l, m)
	}

	for _, m := range l {
		m["pattern"] = newString
	}
	return l
}

func convertWindupDependencyToAnalyzer(windupDependency windup.Dependency) map[string]interface{} {
	name := strings.Replace(strings.Join([]string{windupDependency.GroupId, windupDependency.ArtifactId}, "."), "{*}", "*", -1)
	dependency := map[string]interface{}{}
	if strings.Contains(name, "*") {
		dependency["nameregex"] = name
	} else {
		dependency["name"] = name
	}

	if windupDependency.FromVersion != "" {
		dependency["lowerbound"] = windupDependency.FromVersion
	}
	if windupDependency.ToVersion != "" {
		dependency["upperbound"] = windupDependency.ToVersion
	}
	if windupDependency.FromVersion == "" && windupDependency.ToVersion == "" {
		dependency["lowerbound"] = "0.0.0"
	}
	return dependency
}

func convertWindupGraphQueryJarArchiveModel(gq windup.Graphquery) map[string]interface{} {

	if gq.Property.Name == "fileName" {
		return map[string]interface{}{
			"builtin.file": gq.Property.Value,
		}
	}

	return map[string]interface{}{
		"java.dependency": map[string]string{
			"nameregex": gq.Property.Value,
		},
	}
}

// TODO handle perform fully
func convertWindupPerformToAnalyzer(perform windup.Iteration, where map[string]string) map[string]interface{} {
	ret := map[string]interface{}{}
	tags := []string{}
	if perform.Iteration != nil {
		for _, it := range perform.Iteration {
			converted := convertWindupPerformToAnalyzer(it, where)
			for k, v := range converted {
				ret[k] = v
			}
		}
	}
	if perform.Perform != nil {
		converted := convertWindupPerformToAnalyzer(*perform.Perform, where)
		for k, v := range converted {
			ret[k] = v
		}
	}

	if perform.Hint != nil {
		if len(perform.Hint) != 1 {
			// TODO
			panic("More than one hint in a rule")
			return nil
		}
		hint := perform.Hint[0]
		if hint.Message != "" {
			message := trimMessage(hint.Message)
			// Handle some message replacement
			message = strings.Replace(message, "{", "{{", -1)
			message = strings.Replace(message, "}", "}}", -1)
			ret["message"] = message
		}
	}
	if perform.Technologyidentified != nil {
		for _, ti := range perform.Technologyidentified {
			for _, tag := range ti.Tag {
				tags = append(tags, tag.Name+"="+ti.Name)
			}
		}
	}
	if perform.Technologytag != nil {
		for _, tag := range perform.Technologytag {
			tags = append(tags, tag.Value)
		}
	}
	if perform.Classification != nil {
		for _, classification := range perform.Classification {
			if classification.Tag != nil {
				tags = append(tags, classification.Tag...)
			}
			if classification.Title != "" {
				tags = append(tags, classification.Title)
			}
		}
		// TODO perform.Classification.(Link|Effort|Categoryid|Of|Description|Quickfix|Issuedisplaymode)
	}
	if perform.Lineitem != nil {
		if len(perform.Lineitem) != 1 {
			// TODO
			panic("More than one hint in a rule")
			return nil
		}
		li := perform.Lineitem[0]
		if li.Message != "" {
			message := trimMessage(li.Message)
			// Handle some message replacement
			message = strings.Replace(message, "{package}.{prefix}{type}", "{{name}}", -1)
			message = strings.Replace(message, "{prefix}{type}", "{{type}}", -1)
			ret["message"] = message
		}
	}
	if ret["tag"] != nil {
		ret["tag"] = append(ret["tag"].([]string), tags...)
	} else {
		ret["tag"] = tags
	}
	return ret
}

func substituteWhere(where map[string]string, pattern string) string {
	newString := pattern
	for k, v := range where {
		newString = strings.ReplaceAll(newString, "{"+k+"}", v)
	}
	return newString
}

func trimMessage(s string) string {
	lines := strings.Split(s, "\n")
	cleanLines := []string{}
	for _, line := range lines {
		cleaned := strings.Trim(line, "\n \t '")
		if cleaned != "" {
			cleanLines = append(cleanLines, cleaned)
		}
	}
	return strings.Join(cleanLines, ". ")
}

func flattenWhere(wheres []windup.Where) map[string]string {
	patterns := map[string]string{}
	if wheres != nil && len(wheres) > 0 {
		for _, where := range wheres {
			// Where.Matches seems to always be length 1
			patterns[where.Param] = where.Matches[0].Pattern
		}
	}
	return patterns
}

func writeYAML(content interface{}, dest string) error {
	file, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := yaml.NewEncoder(file)

	err = enc.Encode(content)
	if err != nil {
		return err
	}
	return nil
}
