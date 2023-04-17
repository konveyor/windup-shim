package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"github.com/konveyor/analyzer-lsp/hubapi"
	"gopkg.in/yaml.v2"
)

const (
	JAVA_PROJECT_DIR = "java-project"

	POM_XML = `
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
	<groupId>org.sample</groupId>
	<artifactId>sample-project</artifactId>
    <version>0.0.1</version>
	<name>Sample Project</name>
</project>
`
	BASE_DISCOVERY_RULES = `---
- ruleID: windup-discover-ejb-configuration
  tag: ["EJB XML"]
  when:
    builtin.xml:
      xpath: "/(jboss:ejb-jar or ejb-jar)"
- ruleID: windup-discover-spring-configuration
  tag: ["Spring XML"]
  when:
    builtin.xml:
      xpath: "/beans"
- ruleID: windup-discover-jpa-configuration
  tag: ["JPA XML"]
  when:
    or:
      - builtin.xml:
          xpath: '/persistence[boolean(namespace-uri(/persistence)="http://java.sun.com/xml/ns/persistence")]'
      - builtin.xml:
          xpath: '/persistence[boolean(namespace-uri(/persistence)="http://xmlns.jcp.org/xml/ns/persistence")]'
      - builtin.xml:
          xpath: '/persistance[boolean(namespace-uri(/persistence)="https://jakarta.ee/xml/ns/persistence"])'
- ruleID: windup-discover-web-configuration
  tag: ["Web XML"]
  when:
    # TODO extract version as in rules-java-ee/addon/src/main/java/org/jboss/windup/rules/apps/javaee/rules/DiscoverWebXmlRuleProvider.java
    builtin.xml:
      xpath: /web-app
`
)

func main() {
	var outputDir, data string
	var failFast bool
	convertCmd := flag.NewFlagSet("convert", flag.ExitOnError)
	convertCmd.StringVar(&outputDir, "outputdir", "analyzer-lsp-rules", "The output location for converted rules")
	testCmd := flag.NewFlagSet("test", flag.ExitOnError)
	testCmd.BoolVar(&failFast, "fail-fast", false, "If true, fail on first test failure")
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runCmd.StringVar(&data, "data", "", "The location of the source code to run the rules against")

	help := "Supported subcommands are convert, run, and test"
	if len(os.Args) < 2 {
		fmt.Println(help)
		return
	}

	switch os.Args[1] {
	case "convert":
		if err := convertCmd.Parse(os.Args[2:]); err == nil {
			if convertCmd.NArg() < 1 {
				fmt.Println("The location of one or more windup XML files is required")
				return
			}
			for _, location := range convertCmd.Args() {
				rulesets := []windup.Ruleset{}
				ruletests := []windup.Ruletest{}
				err := filepath.WalkDir(location, walkXML(location, &rulesets, &ruletests, false))
				if err != nil {
					fmt.Println(err)
				}
				_, err = convertWindupRulesetsToAnalyzer(rulesets, location, outputDir)
				if err != nil {
					log.Fatal(err)
				}
			}

		}
	case "test":
		if err := testCmd.Parse(os.Args[2:]); err == nil {
			if testCmd.NArg() < 1 {
				log.Fatal("The location of one or more windup XML files is required")
			}
			for _, location := range testCmd.Args() {
				rulesets := []windup.Ruleset{}
				ruletests := []windup.Ruletest{}
				err := filepath.WalkDir(location, walkXML(location, &rulesets, &ruletests, false))
				if err != nil {
					fmt.Println(err)
				}
				totalSuccesses := 0
				totalTests := 0
				for _, test := range ruletests {
					fmt.Println("Executing " + test.SourceFile)
					successes, total, err := executeTest(test, location)
					if err != nil {
						// TODO should we exit here?
						fmt.Println(err)
					}
					totalSuccesses += successes
					totalTests += total
					fmt.Printf("Overall success rate: %.2f%% (%d/%d)\n", float32(totalSuccesses)/float32(totalTests)*100, totalSuccesses, totalTests)
					if successes != total && failFast {
						break
					}
				}
				if totalSuccesses != totalTests {
					os.Exit(1)
				}
			}
		}
	case "run":
		if err := runCmd.Parse(os.Args[2:]); err == nil {
			if runCmd.NArg() < 1 {
				fmt.Println("The location of one or more windup XML files is required")
				return
			}
			if data == "" {
				fmt.Println("The location of a data directory is required (-data option)")
				return
			}
			rulesets := []windup.Ruleset{}
			for _, location := range runCmd.Args() {
				err := filepath.WalkDir(location, walkXML(location, &rulesets, nil, false))
				if err != nil {
					fmt.Println(err)
				}
			}
			output, dir, err := executeRulesets(rulesets, data)
			fmt.Println(output, dir, err)
		}
	default:
		fmt.Println(help)
	}
}

type javaDirFiles struct {
	fileBytes []byte
	path      string
}

func getJavaFilesFromDirs(dir string) []javaDirFiles {
	files, err := os.ReadDir(dir)
	if err != nil {
		return []javaDirFiles{}
	}
	javaFiles := []javaDirFiles{}
	for _, f := range files {
		if f.IsDir() {
			s := getJavaFilesFromDirs(filepath.Join(dir, f.Name()))
			javaFiles = append(javaFiles, s...)
		}
		if strings.Contains(f.Name(), ".java") {
			b, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				// If we can't read regular files, we need to fix something else
				panic(err)
			}

			javaFiles = append(javaFiles, javaDirFiles{
				fileBytes: b,
				path:      filepath.Join(dir, f.Name()),
			})
		}
	}
	return javaFiles
}

func executeRulesets(rulesets []windup.Ruleset, datadir string) (string, string, error) {
	datadir, err := filepath.Abs(datadir)
	if err != nil {
		return "", "", err
	}

	javaDataDir := datadir
	if strings.HasSuffix(datadir, "pom.xml") {
		javaDataDir = filepath.Dir(javaDataDir)
	} else if !strings.HasSuffix(datadir, ".jar") {
		// For DataDir with *.java we will create a java-project
		// this will contain an empty pom.xml
		// As well as a src/main/java/com/example/apps/*.java
		javaFiles := getJavaFilesFromDirs(datadir)
		if len(javaFiles) > 0 {
			javaDataDir = filepath.Join(datadir, JAVA_PROJECT_DIR)
			appDir := filepath.Join(javaDataDir, "src", "main", "java", "com", "example", "apps")
			err := os.MkdirAll(appDir, os.ModeDir)
			if err != nil {
				return "", "", err
			}
			for _, f := range javaFiles {
				if strings.Contains(f.path, appDir) {
					// If we re-run, you can find these files now, lets skip them.
					continue
				}
				rel, err := filepath.Rel(datadir, f.path)
				if err != nil {
					return "", "", err
				}
				newFilePath := filepath.Join(appDir, rel)
				err = os.MkdirAll(filepath.Dir(newFilePath), os.ModeDir)
				if err != nil {
					return "", "", err
				}
				err = os.WriteFile(newFilePath, f.fileBytes, 0666)
				if err != nil {
					return "", "", err
				}
			}

			// If there is a pom file, in the data dir we will copy this into the java directory.
			_, err = os.Stat(filepath.Join(datadir, "pom.xml"))
			if err == nil {
				original, err := os.Open(filepath.Join(datadir, "pom.xml"))
				if err != nil {
					return "", "", err
				}
				defer original.Close()
				target, err := os.Create(filepath.Join(javaDataDir, "pom.xml"))
				if err != nil {
					return "", "", err
				}
				defer target.Close()
				_, err = io.Copy(target, original)
				if err != nil {
					return "", "", err
				}
			} else {
				err = os.WriteFile(filepath.Join(datadir, JAVA_PROJECT_DIR, "pom.xml"), []byte(POM_XML), 0644)
				if err != nil {
					return "", "", err
				}
			}
		}
	}
	sourceFiles := []string{}
	converted := [][]map[string]interface{}{}
	for _, ruleset := range rulesets {
		sourceFiles = append(sourceFiles, ruleset.SourceFile)
		converted = append(converted, convertWindupRulesetToAnalyzer(ruleset))
	}
	dir, err := os.MkdirTemp("", "analyzer-lsp")
	if err != nil {
		return "", "", err
	}
	os.Mkdir(filepath.Join(dir, "rules"), os.ModePerm)
	fmt.Println(dir)
	// Write base discovery rule to disk
	err = os.WriteFile(filepath.Join(dir, "rules", "0.yaml"), []byte(BASE_DISCOVERY_RULES), 0666)
	if err != nil {
		return "", dir, err
	}
	// write ruleset to disk
	for i, ruleset := range converted {
		path := filepath.Join(dir, "rules", strconv.Itoa(i+1)+".yaml")
		err = writeYAML(ruleset, path)
		if err != nil {
			return "", dir, err
		}
	}
	err = writeYAML(map[string]interface{}{"name": "test-ruleset"}, filepath.Join(dir, "rules", "ruleset.yaml"))
	if err != nil {
		return "", dir, err
	}
	// Template config file for analyzer
	providerConfig := []map[string]interface{}{map[string]interface{}{
		"name":           "java",
		"location":       javaDataDir,
		"binaryLocation": "/jdtls/bin/jdtls",
		"providerSpecificConfig": map[string]string{
			"bundles": "/jdtls/java-analyzer-bundle/java-analyzer-bundle.core/target/java-analyzer-bundle.core-1.0.0-SNAPSHOT.jar",
		},
	},
		{
			"name":     "builtin",
			"location": datadir,
		}}
	err = writeJSON(providerConfig, filepath.Join(dir, "provider_config.json"))
	if err != nil {
		return "", dir, err
	}
	args := []string{"-provider-settings", filepath.Join(dir, "/provider_config.json"), "-rules", filepath.Join(dir, "rules"), "-output-file", filepath.Join(dir, "violations.yaml")}
	debugCmd := strings.Join(append([]string{"dlv debug /analyzer-lsp/main.go --"}, args...), " ")
	cmd := exec.Command("konveyor-analyzer", args...)
	debugInfo := map[string]interface{}{
		"debugCmd":   debugCmd,
		"cmd":        strings.Join(append([]string{"konveyor-analyzer"}, args...), " "),
		"sourceFile": sourceFiles,
	}
	writeYAML(debugInfo, filepath.Join(dir, "debug.yaml"))
	stdout, err := cmd.Output()
	if exitError, ok := err.(*exec.ExitError); ok {
		fmt.Printf("\n\n UNABLE TO RUN: %v\n\n\n", exitError)
	}

	debugInfo["err"] = err
	debugInfo["output"] = string(stdout)
	writeYAML(debugInfo, filepath.Join(dir, "debug.yaml"))

	return string(stdout), dir, err
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

func writeJSON(content interface{}, dest string) error {
	file, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)

	err = enc.Encode(content)
	if err != nil {
		return err
	}
	return nil
}

func executeTest(test windup.Ruletest, location string) (int, int, error) {
	violations, err := getViolations(test)
	total := 0
	successes := 0
	for _, ruleset := range test.Ruleset {
		for _, rule := range ruleset.Rules.Rule {
			total += 1
			if rule.When.Not != nil {
				if len(rule.When.Not) > 1 {
					panic("Hopefully nots can only be length 1")
				}
				if success, numFound, numRequired := runTestRule(rule.When.Not[0], violations); success {
					successes += 1
					fmt.Printf("├ PASS (needed %d, got %d): %s\n", numRequired, numFound, rule.Id)
				} else {
					if len(rule.Perform.Fail) == 1 {
						fmt.Printf("├ FAIL (needed %d, got %d): %s (%s)\n", numRequired, numFound, rule.Id, rule.Perform.Fail[0])
					} else {
						fmt.Printf("├ FAIL (needed %d, got %d): %s (%v)\n", numRequired, numFound, rule.Id, rule.Perform)
					}
				}
			} else {
				if success, numFound, numRequired := runTestRule(rule.When, violations); !success {
					successes += 1
					fmt.Printf("├ PASS (needed %d, got %d): %s\n", numRequired, numFound, rule.Id)
				} else {
					if len(rule.Perform.Fail) == 1 {
						fmt.Printf("├ FAIL (needed %d, got %d): %s (%s)\n", numRequired, numFound, rule.Id, rule.Perform.Fail[0])
					} else {
						fmt.Printf("├ FAIL (needed %d, got %d): %s (%v)\n", numRequired, numFound, rule.Id, rule.Perform)
					}
				}
			}
		}
	}
	fmt.Printf("success rate: %.2f%% (%d/%d)\n", float32(successes)/float32(total)*100, successes, total)
	return successes, total, err
}

func getViolations(test windup.Ruletest) ([]hubapi.RuleSet, error) {
	rulesets := []windup.Ruleset{}
	if len(test.RulePath) == 0 {
		// use the test name, to move up a folder and get the rule
		dir, name := filepath.Split(test.SourceFile)
		name = strings.Replace(name, ".test", "", -1)
		rulePath, err := filepath.Abs(filepath.Join(dir, "..", name))
		if err != nil {
			return nil, err
		}

		test.RulePath = append(test.RulePath, rulePath)
	}
	for _, path := range test.RulePath {
		f, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		// If the rule path is a dir, then we need to convert all the rulesets in the dir.
		if f.IsDir() {
			files, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}
			for _, rulesetFile := range files {
				if rulesetFile.IsDir() {
					// If it is a dir, then we just ignore it.
					continue
				}
				ruleset := processWindupRuleset(filepath.Join(path, rulesetFile.Name()))
				if ruleset != nil {
					rulesets = append(rulesets, *ruleset)
				}
			}
		} else {
			ruleset := processWindupRuleset(path)
			if ruleset != nil {
				rulesets = append(rulesets, *ruleset)
			}
		}
	}
	_, dir, err := executeRulesets(rulesets, test.TestDataPath)
	if err != nil {
		return nil, err
	}
	violationsFile, err := os.Open(filepath.Join(dir, "violations.yaml"))
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(violationsFile)
	if err != nil {
		return nil, err
	}
	var violations []hubapi.RuleSet
	err = yaml.Unmarshal(content, &violations)
	if err != nil {
		return nil, err
	}
	return violations, nil
}

func runTestRule(rule windup.When, violations []hubapi.RuleSet) (bool, int, int) {
	if violations == nil {
		return false, 0, 0
	}

	matchesRequired := 1
	hintExists := rule.Hintexists
	classificationExists := rule.Classificationexists
	lineitemExists := rule.Lineitemexists
	technologyStatisticExists := rule.Technologystatisticsexists
	technologyTagExists := rule.Technologytagexists

	if rule.Iterablefilter != nil {
		if len(rule.Iterablefilter) > 1 {
			panic("Hopefully iterablefilters can only be length 1")
		}
		matchesRequired = rule.Iterablefilter[0].Size
		hintExists = rule.Iterablefilter[0].Hintexists
		if hintExists == nil && rule.Iterablefilter[0].Tofilemodel != nil {
			hintExists = rule.Iterablefilter[0].Tofilemodel[0].Hintexists
		}
		classificationExists = rule.Iterablefilter[0].Classificationexists
		lineitemExists = rule.Iterablefilter[0].Lineitemexists
		technologyStatisticExists = rule.Iterablefilter[0].Technologystatisticsexists
		technologyTagExists = rule.Iterablefilter[0].Technologytagexists
	}

	var hintRegex *regexp.Regexp
	if hintExists != nil {
		var err error
		hintRegexString := hintExists[0].Message
		hintRegex, err = regexp.Compile(hintRegexString)
		if err != nil {
			fmt.Printf("unable to get regex out of hint: %#v\n", err)
		}
	}
	var lineItemExistsRegex *regexp.Regexp
	if lineitemExists != nil {
		var err error
		lineItemExistsRegexString := lineitemExists[0].Message
		lineItemExistsRegex, err = regexp.Compile(lineItemExistsRegexString)
		if err != nil {
			fmt.Printf("unable to get regex out of hint: %#v\n", err)
		}
	}

	foundTags := map[string]bool{}
	for _, ruleset := range violations {
		for _, violation := range ruleset.Violations {
			for _, tag := range violation.Tags {
				foundTags[tag] = true
			}
		}
	}

	numFound := 0
	var tags []string
	if classificationExists != nil {
		for _, c := range classificationExists {
			tags = append(tags, strings.ReplaceAll(c.Classification, `\`, ""))
		}
	} else if technologyStatisticExists != nil {
		for _, t := range technologyStatisticExists {
			for _, tag := range t.Tag {
				tags = append(tags, tag.Name)
				for foundTag, _ := range foundTags {
					// The test checks for a prefix that's an attr on the techonology-statistic-exist and that it has a suffix which is the name of a technology
					if strings.HasPrefix(foundTag, t.Name) && strings.HasSuffix(foundTag, tag.Name) {
						numFound += 1
					}
				}
			}
		}
		return numFound >= matchesRequired, numFound, matchesRequired
	} else if technologyTagExists != nil {
		for _, t := range technologyTagExists {
			tags = append(tags, t.Technologytag)
		}
	}

	if len(tags) != 0 {
		for _, tag := range tags {
			if _, ok := foundTags[tag]; ok {
				numFound += 1
			}
		}
		return numFound >= matchesRequired, numFound, matchesRequired
	}

	for _, ruleset := range violations {
		for _, violation := range ruleset.Violations {
			for _, incident := range violation.Incidents {
				if hintExists != nil {
					if hintRegex.MatchString(incident.Message) {
						numFound += 1
					}
				} else if lineitemExists != nil {
					if lineItemExistsRegex.MatchString(incident.Message) {
						numFound += 1
					}
				} else {
					// TODO(fabianvf) need to figure out why we're hitting this
					fmt.Println("no test task found")
					break
				}
			}
		}
	}
	return numFound >= matchesRequired, numFound, matchesRequired
}

func convertWindupRulesetToAnalyzer(ruleset windup.Ruleset) []map[string]interface{} {
	// TODO Ruleset.Metadata
	// TODO Ruleset.PackageMapping
	// TODO Ruleset.Filemapping
	// TODO Ruleset.Javaclassignore
	rules := []map[string]interface{}{}
	for i, windupRule := range ruleset.Rules.Rule {
		// formatted, _ := yaml.Marshal(windupRule)
		// fmt.Println(string(formatted))
		rule := map[string]interface{}{
			"ruleID": ruleset.SourceFile + "-" + strconv.Itoa(i),
		}
		where := flattenWhere(windupRule.Where)
		if !reflect.DeepEqual(windupRule.When, windup.When{}) {
			when := convertWindupWhenToAnalyzer(windupRule.When, where)
			if len(when) == 1 {
				rule["when"] = when[0]
			} else if len(when) > 1 {
				rule["when"] = map[string]interface{}{"or": when}
			} else {
				continue
			}
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

func convertWindupRulesetsToAnalyzer(windups []windup.Ruleset, baseLocation, outputDir string) (map[string][][]map[string]interface{}, error) {
	outputRulesets := map[string][][]map[string]interface{}{}
	for _, windupRuleset := range windups {
		ruleset := convertWindupRulesetToAnalyzer(windupRuleset)
		yamlPath := strings.Replace(filepath.Join(outputDir, strings.Replace(windupRuleset.SourceFile, baseLocation, "", 1)), ".xml", ".yaml", 1)
		if reflect.DeepEqual(ruleset, map[string]interface{}{}) {
			continue
		}
		outputRulesets[yamlPath] = append(outputRulesets[yamlPath], ruleset)
	}
	for path, ruleset := range outputRulesets {
		dirName := filepath.Dir(path)
		err := os.MkdirAll(dirName, 0777)
		if err != nil {
			fmt.Printf("Skipping because of an error creating %s: %s\n", path, err.Error())
			continue
		}
		err = writeYAML(ruleset, path)
		if err != nil {
			fmt.Printf("Skipping because of an error writing to %s: %s\n", path, err.Error())
			continue
		}
	}
	return outputRulesets, nil
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

func convertWinupGraphQueryJarArchiveModel(gq windup.Graphquery) map[string]interface{} {
	m := map[string]interface{}{
		"nameregex": gq.Property.Value,
	}
	return m
}

func convertWindupWhenToAnalyzer(windupWhen windup.When, where map[string]string) []map[string]interface{} {
	//
	// TODO Rule.When
	// TODO - Graphquery
	conditions := []map[string]interface{}{}
	if windupWhen.Graphquery != nil {
		for _, gq := range windupWhen.Graphquery {
			// JarArchiveModel is a special case for deps
			// that are actually included in a lib folder as jars
			if gq.Discriminator == "JarArchiveModel" {
				conditions = append(conditions, map[string]interface{}{"java.dependency": convertWinupGraphQueryJarArchiveModel(gq)})
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
			converted := convertWindupWhenToAnalyzer(condition, where)
			for _, c := range converted {
				whens = append(whens, c)
			}
		}
		conditions = append(conditions, map[string]interface{}{"and": whens})
	}
	if windupWhen.Or != nil {
		whens := []map[string]interface{}{}
		for _, condition := range windupWhen.Or {
			converted := convertWindupWhenToAnalyzer(condition, where)
			for _, c := range converted {
				whens = append(whens, c)
			}
		}
		conditions = append(conditions, map[string]interface{}{"or": whens})
	}
	if windupWhen.Not != nil {
		for _, condition := range windupWhen.Not {
			converted := convertWindupWhenToAnalyzer(condition, where)
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
			pattern := strings.Replace(substituteWhere(where, jc.References), "{*}", "*", -1)
			pattern = strings.Replace(pattern, "(*)", "*", -1)
			pattern = strings.Replace(pattern, ".*", "*", -1)
			// Make some .* regesx's more generic.
			// TODO: we may need to come back and figure out if we have to deal with
			// capture groups and stuff.
			pattern = strings.Replace(pattern, `(\.*)?\.`, ".*", -1)
			pattern = strings.Replace(pattern, `.[^.]+`, "*", -1)
			pattern = strings.Replace(pattern, `[^.]+`, "*", -1)
			pattern = strings.Replace(pattern, `(\.[^.]*)*`, ".*", -1)
			pattern = strings.Replace(pattern, `(?+[^.]*`, "", -1)
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
			// TODO find an actual way to deal with namespaces
			matches := xf.Matches
			if xf.Namespace != nil {
				for _, ns := range xf.Namespace {
					matches = strings.Replace(strings.Replace(matches, "windup:", "", -1), ns.Prefix+":", "", -1)
				}
			}
			xmlCond := map[string]interface{}{
				"xpath": substituteWhere(where, matches),
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
	return conditions
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
		if hint.Title != "" {
			hint.Message = fmt.Sprintf("%v\n%v", hint.Title, hint.Message)
		}
		if hint.Message != "" {
			message := trimMessage(hint.Message)
			message = strings.Replace(message, "{package}.{prefix}{type}", "{{name}}", -1)
			message = strings.Replace(message, "{prefix}{type}", "{{type}}", -1)
			// Handle some message replacement
			ret["message"] = message
		}
	}
	if perform.Technologyidentified != nil {
		for _, ti := range perform.Technologyidentified {
			for _, tag := range ti.Tag {
				tags = append(tags, ti.Name+" - "+tag.Name)
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

func processWindupRuleset(path string) *windup.Ruleset {
	xmlFile, err := os.Open(path)
	if err != nil {
		fmt.Printf("Skipping %s because of an error opening the file: %s\n", path, err.Error())
		return nil
	}
	defer xmlFile.Close()
	content, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		fmt.Printf("Skipping %s because of an error reading the file: %s\n", path, err.Error())
		return nil
	}
	var ruleset windup.Ruleset

	err = xml.Unmarshal(content, &ruleset)
	if err != nil {
		fmt.Printf("Skipping %s because of an error unmarhsaling the file: %s\n", path, err.Error())
		return nil
	}
	if reflect.ValueOf(ruleset).IsZero() {
		fmt.Printf("Skipping %s because it is not a ruleset\n", path)
		return nil
	}

	ruleset.SourceFile = path
	return &ruleset
}

func processWindupRuletest(path string) *windup.Ruletest {
	xmlFile, err := os.Open(path)
	if err != nil {
		fmt.Printf("Skipping %s because of an error opening the file: %s\n", path, err.Error())
		return nil
	}
	defer xmlFile.Close()
	content, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		fmt.Printf("Skipping %s because of an error reading the file: %s\n", path, err.Error())
		return nil
	}
	var ruletest windup.Ruletest
	err = xml.Unmarshal(content, &ruletest)
	if err != nil {
		fmt.Printf("Skipping %s because of an error unmarhsaling the file: %s\n", path, err.Error())
		return nil
	}
	if reflect.ValueOf(ruletest).IsZero() {
		fmt.Printf("Skipping %s because it is not a ruletest\n", path)
		return nil
	}
	ruletest.SourceFile = path
	// TODO Do we want to make this not relative or something?
	ruletest.TestDataPath = filepath.Join(filepath.Dir(path), ruletest.TestDataPath)
	rulepaths := []string{}
	for _, rulepath := range ruletest.RulePath {
		rulepaths = append(rulepaths, filepath.Join(filepath.Dir(path), rulepath))
	}
	ruletest.RulePath = rulepaths
	return &ruletest
}

func walkXML(root string, rulesets *[]windup.Ruleset, ruletests *[]windup.Ruletest, writeYAML bool) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if !strings.HasSuffix(path, ".xml") {
			// fmt.Printf("Skipping %s because it is not a ruleset\n", path)
			return nil
		}
		if strings.HasSuffix(path, ".test.xml") && ruletests != nil {
			ruletest := processWindupRuletest(path)
			if ruletest != nil {
				*ruletests = append(*ruletests, *ruletest)
			}
		} else if rulesets != nil {
			ruleset := processWindupRuleset(path)
			if ruleset != nil {
				*rulesets = append(*rulesets, *ruleset)
			}
		}
		return err
	}
}
