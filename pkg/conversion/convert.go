package conversion

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"github.com/konveyor-ecosystem/kantra/pkg/testing"
	"github.com/konveyor/analyzer-lsp/engine"
	engineLabels "github.com/konveyor/analyzer-lsp/engine/labels"
	"github.com/konveyor/analyzer-lsp/output/v1/konveyor"
	"gopkg.in/yaml.v2"
)

type analyzerRules struct {
	rules        []map[string]interface{}
	metadata     windup.Metadata
	relativePath string
	sourcePath   string
}

func ConvertWindupRulesetsToAnalyzer(windups []windup.Ruleset, baseLocation, outputDir string, flattenRulesets bool, writeDisoveryRule bool) (map[string]*analyzerRules, error) {
	if writeDisoveryRule {
		err := writeDiscoveryRules(outputDir)
		if err != nil {
			return nil, err
		}
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
				sourcePath:   windupRuleset.SourceFile,
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

// ConvertWindupRuletestsToAnalyzer converts windup XML tests into the new YAML format
func ConvertWindupRuletestsToAnalyzer(windupTests []windup.Ruletest, windupRulesets []windup.Ruleset, analyzerRulesets map[string]*analyzerRules) error {
	analyzerTests := []testing.TestsFile{}
	totalTestsFound := 0
	validTests := 0
	// findConvertedPath given path of a XML rules file, return path of the YAML rules file we converted
	findConvertedPath := func(path string, analyzerRulesets map[string]*analyzerRules) string {
		for yamlPath, ruleset := range analyzerRulesets {
			if strings.Contains(ruleset.sourcePath, path) {
				return yamlPath
			}
		}
		return ""
	}
	// one windup tests file can have tests for multiple rules files
	// we want to group tests by distinct rules files. moreover, there
	// could be multiple windup tests testing the same rule, we group
	// tests by rules and convert them into test cases of the same rule instead
	analyzerTestsFile := map[string]*testing.TestsFile{}
	for _, testsFile := range windupTests {
		if testsFile.RulePath == nil || len(testsFile.RulePath) == 0 {
			testsFile.RulePath = []string{
				strings.Replace(
					strings.Replace(testsFile.SourceFile, "test.xml", "xml", 1),
					"tests/", "", 1),
			}
		}
		for _, windupTests := range testsFile.Ruleset {
			for _, windupTestCase := range windupTests.Rules.Rule {
				totalTestsFound += 1
				analyzerTC := convertWhenToAnalyzerTestCase(windupTestCase.When)
				// find where the rule for this test is
				foundRule, foundPath := findRuleForWindupTestCase(testsFile, windupTestCase, analyzerTC, windupRulesets)
				if foundRule != nil && analyzerTC != nil {
					validTests += 1
					analyzerTC.RuleID = foundRule.Id
					foundPath = findConvertedPath(foundPath, analyzerRulesets)
					_, found := analyzerTestsFile[foundPath]
					if !found {
						analyzerTestsFilePath := strings.Replace(foundPath, ".yaml", ".test.yaml", 1)
						analyzerTestsFilePath = filepath.Join(
							filepath.Dir(analyzerTestsFilePath), "tests", filepath.Base(analyzerTestsFilePath))
						analyzerTestDataPath := filepath.Join(
							filepath.Dir(analyzerTestsFilePath), "data",
							strings.ReplaceAll(filepath.Base(analyzerTestsFilePath), ".windup.test.yaml", ""))
						analyzerTestDataRelativePath := strings.ReplaceAll(analyzerTestDataPath, filepath.Dir(analyzerTestsFilePath), ".")
						analyzerTestsFile[foundPath] = &testing.TestsFile{
							Path: analyzerTestsFilePath,
							Providers: []testing.ProviderConfig{
								{Name: "java", DataPath: analyzerTestDataRelativePath},
								{Name: "builtin", DataPath: analyzerTestDataRelativePath},
							},
							RulesPath: filepath.Join("..", filepath.Base(foundPath)),
							Tests: []testing.Test{{
								RuleID:    foundRule.Id,
								TestCases: []testing.TestCase{},
							}},
						}

						err := os.MkdirAll(filepath.Dir(analyzerTestDataPath), 0755)
						if err != nil {
							fmt.Printf("failed ceating directories for test data in %s\n", filepath.Dir(analyzerTestsFilePath))
							continue
						}
						err = copyTestData(testsFile.TestDataPath, analyzerTestDataPath)
						if err != nil {
							fmt.Printf("failed copying test data from %s to %s - %v\n", testsFile.TestDataPath, analyzerTestDataPath, err)
							continue
						}
					}
					var existingTest *testing.Test
					for idx := range analyzerTestsFile[foundPath].Tests {
						analyzerTest := &analyzerTestsFile[foundPath].Tests[idx]
						if analyzerTest.RuleID == foundRule.Id {
							existingTest = analyzerTest
							analyzerTC.Name = fmt.Sprintf("tc-%d", len(existingTest.TestCases)+1)
							existingTest.TestCases = append(existingTest.TestCases, *analyzerTC)
							break
						}
					}
					if existingTest == nil {
						analyzerTC.Name = "tc-1"
						existingTest = &testing.Test{
							RuleID:    foundRule.Id,
							TestCases: []testing.TestCase{*analyzerTC},
						}
						analyzerTestsFile[foundPath].Tests = append(analyzerTestsFile[foundPath].Tests, *existingTest)
					}
				} else {
					fmt.Printf("couldn't convert test %s\n", windupTestCase.Id)
				}
			}
		}
	}

	for _, testsFile := range analyzerTestsFile {
		content, err := yaml.Marshal(testsFile)
		if err != nil {
			fmt.Printf("failed marshaling tests file %s\n", testsFile.Path)
			continue
		}
		err = os.WriteFile(testsFile.Path, content, 0644)
		if err != nil {
			fmt.Printf("failed writing test to file %s\n", testsFile.Path)
			continue
		}
	}

	fmt.Printf("total files %d, total tcs %d, valid %d\n", len(analyzerTests), totalTestsFound, validTests)
	return nil
}

func convertWhenToAnalyzerTestCase(test windup.When) *testing.TestCase {
	clean := func(m string) string {
		m = regexp.MustCompile(`[^\.]\*$`).ReplaceAllString(m, ".*")
		m = regexp.MustCompile(`[$^\\]`).ReplaceAllString(m, "")
		m = strings.Replace(m, "\n", "", -1)
		m = regexp.MustCompile(`\s{2,}`).ReplaceAllString(m, " *")
		m = strings.TrimSpace(m)
		return m
	}
	switch {
	case test.Not != nil && len(test.Not) > 0:
		return convertWhenToAnalyzerTestCase(test.Not[0])
	case test.And != nil && len(test.And) > 0:
		return convertWhenToAnalyzerTestCase(test.And[0])
	case test.Or != nil && len(test.Or) > 0:
		return convertWhenToAnalyzerTestCase(test.Or[0])
	case test.Classificationexists != nil && len(test.Classificationexists) > 0:
		return &testing.TestCase{
			HasTags: []string{clean(test.Classificationexists[0].Classification)},
		}
	case test.Technologystatisticsexists != nil && len(test.Technologystatisticsexists) > 0:
		return &testing.TestCase{
			HasTags: []string{clean(test.Technologystatisticsexists[0].Name)},
		}
	case test.Technologytagexists != nil && len(test.Technologytagexists) > 0:
		return &testing.TestCase{
			HasTags: []string{clean(test.Technologytagexists[0].Technologytag)},
		}
	case test.Tofilemodel != nil && len(test.Tofilemodel) > 0:
		tf := test.Tofilemodel[0]
		return convertWhenToAnalyzerTestCase(windup.When{
			Classificationexists:       tf.Classificationexists,
			Hintexists:                 tf.Hintexists,
			Lineitemexists:             tf.Lineitemexists,
			Technologystatisticsexists: tf.Technologystatisticsexists,
			Technologytagexists:        tf.Technologytagexists,
		})
	case test.Iterablefilter != nil && len(test.Iterablefilter) > 0:
		it := test.Iterablefilter[0]
		tc := convertWhenToAnalyzerTestCase(windup.When{
			Classificationexists:       it.Classificationexists,
			Technologystatisticsexists: it.Technologystatisticsexists,
			Technologytagexists:        it.Technologytagexists,
			Hintexists:                 it.Hintexists,
			Lineitemexists:             it.Lineitemexists,
			Tofilemodel:                it.Tofilemodel,
		})
		if tc != nil && tc.HasIncidents != nil && tc.HasIncidents.CountBased != nil {
			tc.HasIncidents.CountBased.AtLeast = &it.Size
		}
		return tc
	case test.Hintexists != nil && len(test.Hintexists) > 0:
		msg := clean(test.Hintexists[0].Message)
		one := int(1)
		return &testing.TestCase{
			HasIncidents: &testing.IncidentVerification{
				CountBased: &testing.CountBasedVerification{
					MessageMatches: &msg,
					AtLeast:        &one,
				},
			},
		}
	case test.Lineitemexists != nil && len(test.Lineitemexists) > 0:
		msg := clean(test.Lineitemexists[0].Message)
		one := int(1)
		return &testing.TestCase{
			HasIncidents: &testing.IncidentVerification{
				CountBased: &testing.CountBasedVerification{
					MessageMatches: &msg,
					AtLeast:        &one,
				},
			},
		}
	default:
		return nil
	}
}

// getMessageAndTagsFromPerform given a perform, return all messages or tags perform creates
func getMessageAndTagsFromPerform(perform windup.Iteration, where []windup.Where) []string {
	clean := func(m string) string {
		return strings.ReplaceAll(strings.Trim(strings.TrimSpace(m), "*"), "\\", "")
	}
	switch {
	case perform.Hint != nil && len(perform.Hint) > 0:
		hint := perform.Hint[0]
		msg := clean(hint.Message)
		strs := []string{
			clean(hint.Title),
			msg,
		}
		for _, groups := range regexp.MustCompile(`{[A-Za-z0-9]+}`).FindAllStringSubmatch(msg, -1) {
			for _, group := range groups {
				for _, cond := range where {
					v := strings.TrimPrefix(strings.TrimSuffix(group, "}"), "{")
					if strings.Contains(cond.Param, v) && len(cond.Matches) > 0 {
						for _, possibleVal := range strings.Split(cond.Matches[0].Pattern, "|") {
							possibleVal = strings.TrimPrefix(possibleVal, "(")
							possibleVal = strings.TrimSuffix(possibleVal, ")")
							strs = append(strs, strings.ReplaceAll(msg, group, possibleVal))
						}
					}
				}
			}
		}
		return strs
	case perform.Iteration != nil && len(perform.Iteration) > 0:
		strs := []string{}
		for _, it := range perform.Iteration {
			strs = append(strs, getMessageAndTagsFromPerform(it, where)...)
		}
		return strs
	case perform.Classification != nil && len(perform.Classification) > 0:
		strs := []string{}
		for _, cl := range perform.Classification {
			strs = append(strs, clean(cl.Title))
			for _, t := range cl.Tag {
				strs = append(strs, clean(t))
			}
		}
		return strs
	case perform.Technologytag != nil && len(perform.Technologytag) > 0:
		strs := []string{}
		for _, tt := range perform.Technologytag {
			strs = append(strs, clean(tt.Value))
		}
		return strs
	case perform.Technologyidentified != nil && len(perform.Technologyidentified) > 0:
		strs := []string{}
		for _, cl := range perform.Technologyidentified {
			strs = append(strs, clean(cl.Name))
			for _, t := range cl.Tag {
				strs = append(strs, clean(t.Name))
			}
		}
		return strs
	case perform.Perform != nil:
		return getMessageAndTagsFromPerform(*perform.Perform, where)
	default:
		return []string{}
	}
}

// findRuleForWindupTestCase given a test from windup, find its associated rule in test paths
// to find a rule - first, we try to find the rule by ID, but windup tests don't necessarily
// share the rule ID. so second, we try to compare perform field of the rule.
func findRuleForWindupTestCase(testsFile windup.Ruletest, windupTestCase windup.Rule, analyzerTC *testing.TestCase, windupRulesets []windup.Ruleset) (*windup.Rule, string) {
	for _, path := range testsFile.RulePath {
		for _, windupRuleset := range windupRulesets {
			// check if the tests file points to this rules path
			stat, err := os.Stat(path)
			if err == nil {
				if stat.IsDir() && !strings.Contains(windupRuleset.SourceFile,
					strings.Replace(filepath.Base(testsFile.SourceFile), "test.xml", "xml", 1)) {
					continue
				}
				if !stat.IsDir() && !strings.Contains(windupRuleset.SourceFile, filepath.Base(path)) {
					continue
				}
			}
			seenRules := map[string]*windup.Rule{}
			for idx := range windupRuleset.Rules.Rule {
				rule := &windupRuleset.Rules.Rule[idx]
				seenRules[rule.Id] = rule
				// first, try to find rule in the file by id
				if strings.Contains(rule.Id, strings.Replace(windupTestCase.Id, "-test", "", 1)) ||
					strings.Contains(rule.Id, strings.Replace(windupTestCase.Id, "-tests", "", 1)) {
					return rule, windupRuleset.SourceFile
				}
				// second, try to find rule by comparing message & tag fields
				messageOrTagStrings := getMessageAndTagsFromPerform(rule.Perform, rule.Where)
				if analyzerTC != nil {
					if analyzerTC.HasIncidents != nil &&
						analyzerTC.HasIncidents.CountBased.MessageMatches != nil {
						for _, messageStr := range messageOrTagStrings {
							msg := *analyzerTC.HasIncidents.CountBased.MessageMatches
							// if there are more than one templates in the string, only
							// compare until the first template as we can't accurately permute all values
							noOfTemplates := strings.Count(messageStr, "{")
							if noOfTemplates > 1 {
								secondTemplateIdx := strings.Index(strings.Replace(messageStr, "{", ".", 1), "{")
								messageStr = messageStr[:secondTemplateIdx]
								msg = msg[:int(
									math.Min(float64(secondTemplateIdx), float64(len(msg))))]
							}
							if r, err := regexp.Compile(msg); err == nil &&
								r.MatchString(messageStr) {
								return rule, windupRuleset.SourceFile
							}
							if strings.Contains(messageStr, msg) {
								return rule, windupRuleset.SourceFile
							}
						}
					}
					for _, hasTag := range analyzerTC.HasTags {
						// check if the rule is creating this tag
						for _, messageStr := range messageOrTagStrings {
							if messageStr == hasTag {
								return rule, windupRuleset.SourceFile
							}
						}
						// if an exact tag is not found, check for the pattern
						for _, messageStr := range messageOrTagStrings {
							if r, err := regexp.Compile(hasTag); err == nil &&
								r.MatchString(messageStr) {
								return rule, windupRuleset.SourceFile
							}
						}
					}
				}
			}
			// finally, try to find the rule by id with more complex pattern
			if val, ok := seenRules[regexp.MustCompile(`-test-[\da-z-]+$`).ReplaceAllString(windupTestCase.Id, "")]; ok {
				return val, windupRuleset.SourceFile
			}
		}
	}
	return nil, ""
}

// copyTestData copies test data from windup tests to converted tests
func copyTestData(src string, dest string) error {
	if strings.HasSuffix(src, ".jar") {
		return exec.Command("cp", "-r", src, dest).Run()
	}
	// create a dummy java project
	appDir := filepath.Join(dest, "src", "main", "java", "com", "example", "apps")
	err := os.MkdirAll(appDir, 0755)
	if err != nil {
		return fmt.Errorf("failed creating java project dirs in %s - %w", dest, err)
	}
	cmd := exec.Command("find", src, "-type", "f", "-name", "*.java")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed finding java files in %s - %w", src, err)
	}
	for _, file := range strings.Split(string(out), "\n") {
		if file != "" {
			err = exec.Command("cp", file, appDir).Run()
			if err != nil {
				fmt.Printf("failed copying java file %s to %s - %s\n", file, appDir, err.Error())
				continue
			}
		}
	}
	cmd = exec.Command("find", ".", "-type", "f", "-not", "-name", "*.java")
	cmd.Dir = src
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed finding java files in %s - %w", src, err)
	}
	for _, file := range strings.Split(string(out), "\n") {
		if file != "" {
			// maintain original directory structure of non java files
			cmd := exec.Command("cp", "--parent", file, dest)
			cmd.Dir = src
			err = cmd.Run()
			if err != nil {
				fmt.Printf("failed copying file from %s to %s - %s\n", file, appDir, err.Error())
				continue
			}
		}
	}
	// if we find a pom.xml file, copy it to the project base
	if _, err = os.Stat(filepath.Join(src, "pom.xml")); err == nil {
		return exec.Command("cp", filepath.Join(src, "pom.xml"), dest).Run()
	} else {
		err = os.WriteFile(filepath.Join(dest, "pom.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<groupId>org.sample</groupId>
	<artifactId>sample-project</artifactId>
	<version>0.0.1</version>
	<name>Sample Project</name>
</project>
		`), 0644)
		if err != nil {
			return err
		}
	}
	return nil
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
			when = deduplicateFromAs(when)
			if len(when) == 1 {
				rule["when"] = when[0]
			} else if len(when) > 1 {
				if canUseAndToChain(when) {
					rule["when"] = map[string]interface{}{"and": when}
				} else {
					rule["when"] = map[string]interface{}{"or": when}
				}
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
			if perform["message"] != nil {
				rule["message"] = perform["message"]
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
				rule["description"] = perform["description"]
			}
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
		labels = append(labels,
			fmt.Sprintf("%s=%s", konveyor.SourceTechnologyLabel, sourceTech.Id))
	}
	for _, targetTech := range m.TargetTechnology {
		versions := getVersionsFromMavenVersionRange(targetTech.VersionRange)
		for _, version := range versions {
			labels = append(labels,
				fmt.Sprintf("%s=%s%s", konveyor.TargetTechnologyLabel, targetTech.Id, version))
		}
		labels = append(labels,
			fmt.Sprintf("%s=%s", konveyor.TargetTechnologyLabel, targetTech.Id))
	}
	// when both source technology and target technology is absent, this rule
	// was run all the time in windup, add explicit wildcard label on it
	if (m.SourceTechnology == nil && m.TargetTechnology == nil) ||
		(m.SourceTechnology != nil && len(m.SourceTechnology) == 0 &&
			m.TargetTechnology != nil && len(m.TargetTechnology) == 0) {
		labels = append(labels, fmt.Sprintf("%s=%s",
			engineLabels.RuleIncludeLabel, engineLabels.SelectAlways))
	} else {
		if m.SourceTechnology == nil || len(m.SourceTechnology) == 0 {
			labels = append(labels, konveyor.SourceTechnologyLabel)
		}
		if m.TargetTechnology == nil || len(m.TargetTechnology) == 0 {
			labels = append(labels, konveyor.TargetTechnologyLabel)
		}
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
		return []string{fmt.Sprintf("%s-", maxVersion)}
	}
	if maxVersion == "" && match[2] != "" {
		return []string{fmt.Sprintf("%s+", minVersion)}
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
					"pattern":     convertWindupRegex(substituteWhere(where, escapeParens(fc.Pattern))),
					"filePattern": escapeDots(convertWindupRegex(substituteWhere(where, fc.Filename))),
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
			pattern = strings.Replace(pattern, `[^.()]+`, "*", -1)
			pattern = strings.Replace(pattern, `(.[^.]*)*`, "*", -1)
			pattern = strings.Replace(pattern, `+[^.]*?`, "*", -1)
			pattern = strings.Replace(pattern, `[*]`, `\[*\]`, -1)
			pattern = strings.Replace(pattern, `([a-z]+.)`, `*`, -1)
			// remove open paranthesis which will be otherwise interpreted as wildcards
			pattern = regexp.MustCompile(`\(\*$`).ReplaceAllString(pattern, "*")
			pattern = regexp.MustCompile(`\(\)`).ReplaceAllString(pattern, "*")
			pattern = regexp.MustCompile(`\[\]`).ReplaceAllString(pattern, "*")
			// cascade multiple dots and stars
			pattern = regexp.MustCompile(`[\.]{2,}\*`).ReplaceAllString(pattern, ".*")
			pattern = regexp.MustCompile(`[\*]{2,}`).ReplaceAllString(pattern, "*")
			pattern = strings.Replace(pattern, ".(*)?*", ".*", -1)
			// when there are wildcards in the middle of the pattern, make them .*
			// see https://github.com/konveyor/analyzer-lsp/issues/481
			pattern = regexp.MustCompile(`([A-Za-z])\*([A-Za-z])`).ReplaceAllString(pattern, `$1.*$2`)
			// when pattern ends with * and a location is not specified
			// we guess the location based on defined pattern
			if strings.HasSuffix(pattern, "*") && jc.Location == nil {
				locations := []string{}
				match := regexp.MustCompile(`.*?(\w+)[\)\(]*\*$`).FindStringSubmatch(pattern)
				lastWord := ""
				if len(match) > 0 {
					lastWord = match[1]
				}
				// if the last word in the pattern is camel case, it has to be a method
				if lastWord != "" && unicode.IsLower(rune(lastWord[0])) && uppercaseExists(lastWord[1:]) {
					locations = append(locations, "METHOD_CALL")
				} else {
					// if the last word in the pattern is camel case, and the first letter is uppercase, it's probably a class
					if lastWord != "" && unicode.IsUpper(rune(lastWord[0])) && lowercaseExists(lastWord[1:]) {
						locations = append(locations, "IMPORT")
					} else {
						// otherwise, it's probably a package
						locations = append(locations, "PACKAGE")
					}
				}
				jc.Location = locations
			}
			if jc.Location != nil {
				for _, location := range jc.Location {
					condition := convertWindupJavaClassToCondition(jc)
					condition["java.referenced"].(map[string]interface{})["location"] = location
					condition["java.referenced"].(map[string]interface{})["pattern"] = pattern
					conditions = append(conditions, condition)
				}
			} else {
				condition := convertWindupJavaClassToCondition(jc)
				condition["java.referenced"].(map[string]interface{})["pattern"] = pattern
				conditions = append(conditions, condition)
			}
		}
	}
	if windupWhen.Xmlfile != nil {
		for idx, xf := range windupWhen.Xmlfile {
			var condType = "builtin.xml"
			var xmlCond map[string]interface{}

			namespaces := map[string]string{}
			if xf.Namespace != nil {
				for _, ns := range xf.Namespace {
					namespaces[ns.Prefix] = ns.Uri
				}
			}

			if xf.Matches != "" {
				matches := strings.Replace(xf.Matches, "windup:", "", -1)
				xmlCond = map[string]interface{}{
					"xpath":      substituteWhere(where, matches),
					"namespaces": namespaces,
				}
			}

			if xf.Systemid != "" {
				matches := strings.Replace(xf.Matches, "windup:", "", -1)
				xmlCond = map[string]interface{}{
					"xpath":      "//*[@system-id='" + substituteWhere(where, matches) + "']",
					"namespaces": namespaces,
				}
			}

			if xf.Publicid != "" {
				condType = "builtin.xmlPublicID"
				matches := strings.Replace(xf.Matches, "windup:", "", -1)
				xmlCond = map[string]interface{}{
					"regex":      substituteWhere(where, matches),
					"namespaces": namespaces,
				}
			}

			if xmlCond == nil {
				continue
			}
			if xf.In != "" {
				in := substituteWhere(where, xf.In)
				if strings.Contains(in, "{*}") {
					conditions = append(conditions, map[string]interface{}{
						"builtin.file": map[string]interface{}{
							"pattern": strings.Replace(escapeDots(xf.In), "{*}", ".*", -1),
						},
						"as":     fmt.Sprintf("xmlfiles%d", idx+1),
						"ignore": true,
					})
					xmlCond["from"] = fmt.Sprintf("xmlfiles%d", idx+1)
					xmlCond["filepaths"] = fmt.Sprintf("{{xmlfiles%d.filepaths}}", idx+1)
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
				condType: xmlCond,
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
	// escape any empty paranthesis to avoid interpreting them as wildcards
	newString = strings.Replace(newString, `[]`, `\[\]`, -1)
	newString = strings.Replace(newString, `()`, `\(\)`, -1)
	// cascade multiple dots and stars
	newString = regexp.MustCompile(`\.{2,}\*`).ReplaceAllString(newString, ".*")
	newString = regexp.MustCompile(`\*{2,}`).ReplaceAllString(newString, "*")
	for k, v := range whereMap {
		camelK := convertToCamel(k)
		newString = strings.ReplaceAll(newString, "{"+k+"}.", fmt.Sprintf("(?P<%s>%s.)?", camelK, v))
		newString = strings.ReplaceAll(newString, "{"+k+"}", fmt.Sprintf("(?P<%s>%s)?", camelK, v))
		newString = strings.ReplaceAll(newString, "?+", "?")
		newString = strings.TrimRight(newString, "?")
		m := map[string]interface{}{
			"name":               camelK,
			"nameOfCaptureGroup": camelK,
		}
		l = append(l, m)
	}

	for _, m := range l {
		m["pattern"] = convertWindupRegex(newString)
	}
	return l
}

func convertToCamel(fullPattern string) string {
	//If string has dash or space char then we need to convert if it does not, then return it as is
	if !strings.Contains(fullPattern, " ") && !strings.Contains(fullPattern, "-") {
		return fullPattern
	}
	// Convert all issues to spaces to make splitting easier.
	s := strings.ReplaceAll(fullPattern, "-", " ")
	v := strings.Split(s, " ")
	newString := ""
	for i, part := range v {
		if i == 0 {
			newString = newString + strings.ToLower(part)
			continue
		}
		if len(part) > 0 {
			newString += strings.ToUpper(string(part[0])) + part[1:]
		}
	}
	return newString
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

func convertMessageString(m string) string {
	m = strings.Replace(m, "{", "{{", -1)
	m = strings.Replace(m, "}", "}}", -1)
	m = strings.Replace(m, "{package}.{prefix}{type}", "{{name}}", -1)
	m = strings.Replace(m, "{prefix}{type}", "{{type}}", -1)
	customVarsMatch := regexp.MustCompile(`{{([\w- ]+)}}`).FindAllStringSubmatch(m, -1)
	for _, groups := range customVarsMatch {
		if len(groups) > 1 {
			m = strings.Replace(m,
				fmt.Sprintf("{{%s}}", groups[1]),
				fmt.Sprintf("{{%s}}", convertToCamel(groups[1])), -1)
		}
	}
	return m
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
		hint := perform.Hint[0]
		if hint.Message != "" {
			message := trimMessage(hint.Message)
			ret["message"] = convertMessageString(message)
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

			tags = append(tags, classification.Title)
			// we know title will never be nil (see https://github.com/windup/windup/blob/master/config-xml/schema/windup-jboss-ruleset.xsd#L397)
			ret["description"] = classification.Title

			if classification.Description != nil {
				ret["message"] = strings.Join(classification.Description, "\n")
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
			ret["message"] = convertMessageString(message)
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
	re := regexp.MustCompile(`( ){2,}`)
	trimmed := strings.TrimSpace(s)
	return re.ReplaceAllString(trimmed, " ")
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

func uppercaseExists(s string) bool {
	for _, char := range s {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

func lowercaseExists(s string) bool {
	for _, char := range s {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
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

func convertWindupRegex(regex string) string {
	regex = strings.Replace(regex, "{*}", ".*", -1)
	_, err := regexp.Compile(regex)
	if err != nil {
		fmt.Printf("Failed converting regex to valid go format: %s\n", regex)
	}
	return regex
}

func escapeParens(s string) string {
	s = strings.Replace(s, "(", "\\(", -1)
	s = strings.Replace(s, ")", "\\)", -1)
	return s
}

// canUseAndToChain when converting chained conditions, we check if they can
// be ANDed...it improves accuracy: https://github.com/konveyor/rulesets/issues/41
// we can only do this for builtin conditions reliably
func canUseAndToChain(when []map[string]interface{}) bool {
	canDetermine := true
	fromUsed := false
	asUsed := false
	for _, cond := range when {
		for key := range cond {
			// if any one condition is java, we can't make this an AND
			if strings.HasPrefix(key, "java") {
				canDetermine = false
				break
			}
			if key == "from" {
				fromUsed = true
			}
			if key == "as" {
				asUsed = true
			}
		}
	}
	return canDetermine && fromUsed && asUsed
}

func deduplicateFromAs(when []map[string]interface{}) []map[string]interface{} {
	seenAs := map[string]interface{}{}
	deduped := []map[string]interface{}{}
	for _, cond := range when {
		dedupedCond := map[string]interface{}{}
		for key, val := range cond {
			switch key {
			case "or", "and":
				if mapVal, ok := val.([]map[string]interface{}); ok {
					dedupedCond[key] = deduplicateFromAs(mapVal)
				}
			case "as":
				if valStr, ok := val.(string); ok {
					if _, ok := seenAs[valStr]; !ok {
						seenAs[valStr] = nil
						dedupedCond[key] = val
					}
				}
			default:
				dedupedCond[key] = val
			}
		}
		deduped = append(deduped, dedupedCond)
	}
	return deduped
}

func convertWindupJavaClassToCondition(jc windup.Javaclass) map[string]interface{} {
	// TODO handle jc.Annotationlist
	// TODO handle jc.MatchesSource
	// TODO handle jc.In
	condition := map[string]interface{}{
		"java.referenced": map[string]interface{}{},
	}

	if jc.Annotationliteral != nil {
		condition["java.referenced"].(map[string]interface{})["annotated"] = map[string]interface{}{
			"elements": []map[string]interface{}{},
		}
		for _, annotationLiteral := range jc.Annotationliteral {
			if annotationLiteral.Name != "" {
				annotatedContent := condition["java.referenced"].(map[string]interface{})["annotated"].(map[string]interface{})

				elements := append(
					annotatedContent["elements"].([]map[string]interface{}),
					map[string]interface{}{
						"name":  annotationLiteral.Name,
						"value": convertWindupRegex(annotationLiteral.Pattern),
					},
				)
				annotatedContent["elements"] = elements
			}
		}

	}

	if jc.Annotationtype.Pattern != "" {
		annotated := condition["java.referenced"].(map[string]interface{})["annotated"]
		if annotated == nil {
			annotated = map[string]interface{}{}
		}
		annotated.(map[string]interface{})["pattern"] = jc.Annotationtype.Pattern
	}

	if jc.As != "" {
		condition["as"] = jc.As
		// TODO (shurley): Only set when something is going to use this as block
		// condition["ignore"] = true
	}
	if jc.From != "" {
		condition["from"] = jc.From
	}

	return condition
}
