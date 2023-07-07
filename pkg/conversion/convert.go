package conversion

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"github.com/konveyor/analyzer-lsp/engine"
	"github.com/konveyor/analyzer-lsp/output/v1/konveyor"
	"gopkg.in/yaml.v2"
)

type analyzerRules struct {
	rules        []map[string]interface{}
	metadata     windup.Metadata
	relativePath string
}

func ConvertWindupRulesetsToAnalyzer(windups []windup.Ruleset, baseLocation, outputDir string, flattenRulesets bool) (map[string]*analyzerRules, error) {
	// Write discovery rules
	err := writeDiscoveryRules(outputDir)
	if err != nil {
		return nil, err
	}

	outputRulesets := map[string]*analyzerRules{}
	for idx, windupRuleset := range windups {
		// used for ordering rulesets
		counter := idx + 1
		ruleset := ConvertWindupRulesetToAnalyzer(windupRuleset)
		rulesetRelativePath := strings.Trim(strings.Replace(strings.Replace(windupRuleset.SourceFile, baseLocation, "", 1), filepath.Base(windupRuleset.SourceFile), "", 1), "/")
		rulesetFileName := strings.Replace(filepath.Base(windupRuleset.SourceFile), ".xml", ".yaml", 1)
		// technology-usage rulesets are meant to run after their respective discovery rulesets
		// we don't have such ordering in analyzers, this is a hack to make analyzers pick in order
		if strings.Contains(rulesetFileName, "technology-usage") {
			counter = len(windups) - idx + 1
		}
		yamlPath := filepath.Join(outputDir, rulesetRelativePath, fmt.Sprintf("%.02d-%s", counter, strings.Replace(rulesetFileName, ".windup.yaml", "", 1)), rulesetFileName)
		if flattenRulesets {
			flattenedRelativePath := strings.Split(rulesetRelativePath, string(os.PathSeparator))[0]
			yamlPath = filepath.Join(outputDir, flattenedRelativePath, fmt.Sprintf("%.02d-%s", counter, rulesetFileName))
		}
		if reflect.DeepEqual(ruleset, map[string]interface{}{}) {
			continue
		}
		if _, ok := outputRulesets[yamlPath]; !ok {
			outputRulesets[yamlPath] = &analyzerRules{
				rules:        []map[string]interface{}{},
				metadata:     windupRuleset.Metadata,
				relativePath: rulesetRelativePath,
			}
		}
		outputRulesets[yamlPath].rules = append(outputRulesets[yamlPath].rules, ruleset...)
		outputRulesets[yamlPath].metadata = windupRuleset.Metadata
		outputRulesets[yamlPath].relativePath = rulesetRelativePath
	}
	for path, ruleset := range outputRulesets {
		dirName := filepath.Dir(path)
		err := os.MkdirAll(dirName, 0777)
		if err != nil {
			fmt.Printf("Skipping because of an error creating %s: %s\n", path, err.Error())
			continue
		}
		err = writeRuleset(path, ruleset, flattenRulesets)
		if err != nil {
			fmt.Printf("Skipping because of an error creating ruleset.yaml for %s: %s\n", path, err.Error())
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

func writeRuleset(path string, r *analyzerRules, flattenRulesets bool) error {
	rulesetGoldenFilePath := filepath.Join(filepath.Dir(path), "ruleset.yaml")
	// generate labels for the new ruleset we want to create
	rsLabels := getRulesetLabels(r.metadata)
	rsLabels = append(rsLabels, r.relativePath)
	// find existing ruleset.yaml file and load metadata, this
	// is needed when we don't split rulesets into subdirs, we merge metadata
	ruleset := engine.RuleSet{
		Name:        r.relativePath,
		Description: string(r.metadata.Description),
		Labels:      []string{},
	}
	// when rulesets are flattened, only the rule labels will be used
	if !flattenRulesets {
		ruleset.Labels = rsLabels
	}
	err := writeYAML(ruleset, rulesetGoldenFilePath)
	if err != nil {
		fmt.Printf("Skipping because of an error writing ruleset golden file to %s: %s\n", rulesetGoldenFilePath, err.Error())
		return err
	}
	return nil
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
		labels := getRulesetLabels(ruleset.Metadata)
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
			tags, ok := perform["tag"].([]string)
			if !ok {
				tags = nil
			}
			links := []interface{}{}
			if windupLinks, ok := perform["links"].([]interface{}); ok {
				for _, windupLink := range windupLinks {
					if lnk, ok := windupLink.(windup.Link); ok {
						links = append(links, map[string]interface{}{
							"url":   lnk.HRef,
							"title": lnk.Title,
						})
					}
				}
			}
			rule["links"] = links

			if perform["category"] != nil {
				rule["category"] = perform["category"]
			}
			description := ""
			if perform["message"] != nil {
				rule["message"] = perform["message"]
				// if message doesn't contain a template, add it to the description too
				if msg, ok := perform["message"].(string); ok &&
					!strings.Contains(msg, "{{") {
					description = msg
				}
			}
			if perform["labels"] != nil {
				if performLabels, ok := perform["labels"].([]string); ok {
					labels = append(labels, performLabels...)
				}
			}
			// Dedup tags
			if len(tags) != 0 {
				rule["tag"] = tags
			}
			if rule["message"] == nil && rule["tag"] == nil {
				fmt.Println("\n\nNo action parsed")
				continue
			}
			if perform["effort"] != nil {
				rule["effort"] = perform["effort"]
			}
			if perform["description"] != nil {
				if dsc, ok := perform["description"].(string); ok {
					description = strings.Join([]string{dsc, description}, "\n")
				}
			}
			if description != "" {
				rule["description"] = description
			}
			// for k, v := range perform {
			// 	rule[k] = v
			// }
		} else {
			continue
		}

		// dedup labels
		labelsSet := map[string]bool{}
		dedupLabels := []string{}
		for _, label := range labels {
			if _, ok := labelsSet[label]; !ok {
				labelsSet[label] = true
				dedupLabels = append(dedupLabels, label)
			}
		}
		rule["labels"] = dedupLabels

		// TODO - Iteration
		// TODO Rule.Otherwise
		rules = append(rules, rule)
	}
	return rules
}

func getRulesetLabels(m windup.Metadata) []string {
	labels := []string{}
	// convert source / target technologies to labels
	for _, sourceTech := range m.SourceTechnology {
		versions := getVersionsFromMavenVersionRange(sourceTech.VersionRange)
		for _, version := range versions {
			labels = append(labels,
				fmt.Sprintf("%s=%s%s", konveyor.SourceTechnologyLabel, sourceTech.Id, version))
		}
		if len(versions) == 0 {
			labels = append(labels,
				fmt.Sprintf("%s=%s", konveyor.SourceTechnologyLabel, sourceTech.Id))
		}
	}
	for _, targetTech := range m.TargetTechnology {
		versions := getVersionsFromMavenVersionRange(targetTech.VersionRange)
		for _, version := range versions {
			labels = append(labels,
				fmt.Sprintf("%s=%s%s", konveyor.TargetTechnologyLabel, targetTech.Id, version))
		}
		if len(versions) == 0 {
			labels = append(labels,
				fmt.Sprintf("%s=%s", konveyor.TargetTechnologyLabel, targetTech.Id))
		}
	}
	if m.SourceTechnology == nil || len(m.SourceTechnology) == 0 {
		labels = append(labels, fmt.Sprintf("%s=", konveyor.SourceTechnologyLabel))
	}
	if m.TargetTechnology == nil || len(m.TargetTechnology) == 0 {
		labels = append(labels, fmt.Sprintf("%s=", konveyor.TargetTechnologyLabel))
	}
	if m.Phase != "" {
		labels = append(labels, fmt.Sprintf("phase=%v", m.Phase))
	}
	// rulesets have <tags> too
	labels = append(labels, m.Tag...)
	return labels
}

func getVersionsFromMavenVersionRange(versionRange string) []string {
	versionRange = strings.Trim(versionRange, " ")
	if versionRange == "" {
		return []string{}
	}
	versionRegex := regexp.MustCompile(`^[\(|\[]([\d\.]+)?(, *([\d\.]+)?)*[\]\)]$`)
	match := versionRegex.FindStringSubmatch(versionRange)
	var minVersion, maxVersion string
	if len(match) != 4 {
		fmt.Printf("error matching version range '%s'\n", versionRange)
		return []string{}
	}
	minVersion = match[1]
	maxVersion = match[3]
	if minVersion == "" && maxVersion == "" {
		return []string{}
	}
	if minVersion == "" && match[2] != "" {
		return []string{maxVersion}
	}
	if maxVersion == "" && match[2] != "" {
		return []string{minVersion}
	}
	minVerFloat, err := strconv.ParseFloat(minVersion, 64)
	if err != nil {
		return []string{}
	}
	maxVerFloat, err := strconv.ParseFloat(maxVersion, 64)
	if err != nil {
		return []string{minVersion}
	}
	minVerInt := int(minVerFloat)
	maxVerInt := int(maxVerFloat)
	if strings.HasSuffix(versionRange, ")") {
		maxVerInt -= 1
	}
	if strings.HasPrefix(versionRange, "(") {
		minVerInt += 1
	}
	versions := []string{}
	for i := minVerInt; i <= maxVerInt; i++ {
		versions = append(versions, strconv.Itoa(i))
	}
	return versions
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
			switch gq.Discriminator {
			case "JarArchiveModel":
				conditions = append(conditions,
					convertWindupGraphQueryJarArchiveModel(gq))
			case "JsfSourceFile":
				conditions = append(conditions,
					convertWindupGraphQueryJsfSourceFile(gq))
			case "JspSourceFileModel":
				conditions = append(conditions,
					convertWindupGraphQueryJspSourceFileModel(gq))
			case "TechnologyTagModel":
				conditions = append(conditions,
					map[string]interface{}{"builtin.hasTags": []string{gq.Property.Value}})
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
			//var files string
			//if fc.Filename != "" {
			//files = fc.Filename
			//}
			condition := map[string]interface{}{
				"builtin.filecontent": map[string]interface{}{
					"pattern": strings.Replace(substituteWhere(where, fc.Pattern), "{*}", "*", -1),
					//"filePattern": files,
				},
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
						"builtin.file": map[string]interface{}{
							"pattern": strings.Replace(escapeDots(xf.In), "{*}", ".*", -1),
						},
						"as":     "xmlfiles",
						"ignore": true,
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
				"builtin.file": map[string]interface{}{
					"pattern": strings.Replace(escapeDots(substituteWhere(where, f.Filename)), "{*}", ".*", -1),
				},
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
				"builtin.file": map[string]interface{}{
					"pattern": strings.Replace(escapeDots(substituteWhere(where, f.Filename)), "{*}", ".*", -1),
				},
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
	isRegex := strings.Contains(fmt.Sprintf("%s.%s", windupDependency.GroupId, windupDependency.ArtifactId), "*")
	name := fmt.Sprintf("%s.%s", windupDependency.GroupId, windupDependency.ArtifactId)
	dependency := map[string]interface{}{}
	if isRegex {
		groupId := escapeDots(windupDependency.GroupId)
		groupId = strings.ReplaceAll(groupId, "{*}", ".*")
		artifactId := strings.ReplaceAll(windupDependency.ArtifactId, "{*}", ".*")
		groupEndsWildcard := regexp.MustCompile(`\.\*$`).MatchString(groupId)
		artifactStartsWildcard := regexp.MustCompile(`^\.\*`).MatchString(artifactId)
		name = fmt.Sprintf("%s\\.%s", groupId, artifactId)
		if groupEndsWildcard && artifactStartsWildcard {
			name = fmt.Sprintf("%s%s", groupId, strings.TrimLeft(artifactId, ".*"))
		}
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
			"builtin.file": map[string]interface{}{
				"pattern": gq.Property.Value,
			},
		}
	}

	return map[string]interface{}{
		"java.dependency": map[string]string{
			"nameregex": gq.Property.Value,
		},
	}
}

// Converts graph queries for JspSourceFileModel
func convertWindupGraphQueryJspSourceFileModel(gq windup.Graphquery) map[string]interface{} {
	return map[string]interface{}{
		"or": []map[string]interface{}{
			{
				"builtin.filecontent": map[string]interface{}{
					"pattern":     "<%@\\s*page\\s+[^>]*\\s*import\\s*=\\s*['\"]([^'\"]+)['\"].*?%>",
					"filePattern": ".*\\.(jsp|jspx|tag|tagx)",
				},
			},
			{
				"builtin.filecontent": map[string]interface{}{
					"pattern":     "<%@\\s*taglib\\s+[^>]*\\s*uri\\s*=\\s*['\"]([^'\"]+)['\"].*?%>",
					"filePattern": ".*\\.(jsp|jspx|tag|tagx)",
				},
			},
		},
	}
}

// Converts graph queries for JsfSourceFile
func convertWindupGraphQueryJsfSourceFile(gq windup.Graphquery) map[string]interface{} {
	return map[string]interface{}{
		"builtin.filecontent": map[string]interface{}{
			"pattern":     "(java\\.sun\\.com/jsf/)|(xmlns\\.jcp\\.org/jsf)",
			"filePattern": ".*\\.(jsp|xhtml|jspx)",
		},
	}
}

// TODO handle perform fully
func convertWindupPerformToAnalyzer(perform windup.Iteration, where map[string]string) map[string]interface{} {
	ret := map[string]interface{}{}
	tags := []string{}
	links := []interface{}{}
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
		i, err := strconv.Atoi(fmt.Sprintf("%v", hint.Effort))
		if err == nil {
			ret["effort"] = i
		}

		if len(hint.Tag) != 0 {
			ret["labels"] = hint.Tag
		}

		// some rules only have title, use that as description
		if hint.Title != "" {
			ret["description"] = hint.Title
		}

		if hint.Categoryid != "" {
			ret["category"] = convertWindupCategory(hint.Categoryid)
		}

		if hint.Link != nil {
			for _, lnk := range hint.Link {
				links = append(links, lnk)
			}
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
			description := ""
			if classification.Title != "" {
				tags = append(tags, classification.Title)
				description = classification.Title
			}
			if classification.Description != nil {
				// combine title + description
				ret["description"] = fmt.Sprintf("%s\n%s", description, strings.Join(classification.Description, "\n"))
			}
			if classification.Link != nil {
				for _, lnk := range classification.Link {
					links = append(links, lnk)
				}
			}
			if eff, err := strconv.Atoi(string(classification.Effort)); err == nil {
				ret["effort"] = eff
			}
		}
		// TODO perform.Classification.(Categoryid|Of|Quickfix|Issuedisplaymode)
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
	ret["links"] = links
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

// some dots require escaping where they will be treated as a wildcard otherwise
func escapeDots(inp string) string {
	return regexp.MustCompile(`\.([^*])`).ReplaceAllString(inp, `\.$1`)
}

func writeDiscoveryRules(dir string) error {
	defaultRulesetPath := filepath.Join(dir, "00-discovery")
	err := os.MkdirAll(defaultRulesetPath, os.ModePerm)
	if err != nil {
		return err
	}
	// Write base discovery rule to disk
	err = os.WriteFile(filepath.Join(defaultRulesetPath, "0.yaml"), []byte(GetDiscoveryRules()), 0666)
	if err != nil {
		return err
	}
	// Write base discovery ruleset to disk
	err = os.WriteFile(filepath.Join(defaultRulesetPath, "ruleset.yaml"), []byte(GetDiscoveryRuleset()), 0666)
	if err != nil {
		return err
	}
	return nil
}

func convertWindupCategory(cat string) string {
	switch cat {
	case "mandatory", "cloud-mandatory":
		return string(konveyor.Mandatory)
	case "optional", "cloud-optional":
		return string(konveyor.Optional)
	case "potential":
		return string(konveyor.Potential)
	default:
		return string(konveyor.Potential)
	}
}
