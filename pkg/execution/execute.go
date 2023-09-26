package execution

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/conversion"
	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"github.com/konveyor/analyzer-lsp/output/v1/konveyor"
	"github.com/konveyor/analyzer-lsp/provider"
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
          xpath: '/persistence[boolean(namespace-uri(/persistence)="https://jakarta.ee/xml/ns/persistence")]'
- ruleID: windup-discover-web-configuration
  tag: ["Web XML"]
  when:
    # TODO extract version as in rules-java-ee/addon/src/main/java/org/jboss/windup/rules/apps/javaee/rules/DiscoverWebXmlRuleProvider.java
    builtin.xml:
      xpath: /web-app
`
)

func ExecuteRulesets(rulesets []windup.Ruleset, baseLocation, datadir string) (string, string, error) {
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
	dir, err := os.MkdirTemp("", "analyzer-lsp")
	if err != nil {
		return "", "", err
	}
	fmt.Println(dir)
	sourceFiles := []string{}
	for _, ruleset := range rulesets {
		sourceFiles = append(sourceFiles, ruleset.SourceFile)
	}
	conversion.ConvertWindupRulesetsToAnalyzer(rulesets, baseLocation, filepath.Join(dir, "rules"), true, "")
	// Template config file for analyzer
	providerConfig := []provider.Config{
		{
			Name: "java",
			InitConfig: []provider.InitConfig{
				{
					Location: javaDataDir,
					ProviderSpecificConfig: map[string]interface{}{
						"bundles":       "/jdtls/java-analyzer-bundle/java-analyzer-bundle.core/target/java-analyzer-bundle.core-1.0.0-SNAPSHOT.jar",
						"lspServerPath": "/jdtls/bin/jdtls",
					},
				},
			},
		},
		{
			Name: "builtin",
			InitConfig: []provider.InitConfig{
				{
					Location: datadir,
				},
			},
		}}
	err = writeJSON(providerConfig, filepath.Join(dir, "provider_config.json"))
	if err != nil {
		return "", dir, err
	}
	args := []string{"--provider-settings", filepath.Join(dir, "/provider_config.json"), "--rules", filepath.Join(dir, "rules"), "--output-file", filepath.Join(dir, "violations.yaml")}
	debugCmd := strings.Join(append([]string{"dlv debug /analyzer-lsp/main.go --"}, args...), " ")
	cmd := exec.Command("konveyor-analyzer", args...)
	cmd.Dir = dir
	debugInfo := map[string]interface{}{
		"debugCmd":   debugCmd,
		"cmd":        strings.Join(append([]string{"konveyor-analyzer"}, args...), " "),
		"sourceFile": sourceFiles,
	}
	writeYAML(debugInfo, filepath.Join(dir, "debug.yaml"))
	stdout, err := cmd.CombinedOutput()
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
	yaml.FutureLineWrap()
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

func ExecuteTest(test windup.Ruletest, location string) (int, int, error) {
	violations, err := getViolations(test, location)
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

func getViolations(test windup.Ruletest, baseLocation string) ([]konveyor.RuleSet, error) {
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
		if strings.HasSuffix(path, ".groovy") {
			fmt.Printf("Skipping %s because groovy rulesets are not supported.\n", path)
			continue
		}
		f, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Skipping %s because it did not exist: %v\n", path, err)
			continue
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
				ruleset := windup.ProcessWindupRuleset(filepath.Join(path, rulesetFile.Name()))
				if ruleset != nil {
					rulesets = append(rulesets, *ruleset)
				}
			}
		} else {
			ruleset := windup.ProcessWindupRuleset(path)
			if ruleset != nil {
				rulesets = append(rulesets, *ruleset)
			}
		}
	}
	_, dir, err := ExecuteRulesets(rulesets, baseLocation, test.TestDataPath)
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
	var violations []konveyor.RuleSet
	err = yaml.Unmarshal(content, &violations)
	if err != nil {
		return nil, err
	}
	return violations, nil
}

func runTestRule(rule windup.When, violations []konveyor.RuleSet) (bool, int, int) {
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
		for _, tag := range ruleset.Tags {
			foundTags[tag] = true
		}
	}

	numFound := 0
	var tags []*regexp.Regexp
	if classificationExists != nil {
		for _, c := range classificationExists {
			tags = append(tags, regexp.MustCompile(strings.ReplaceAll(c.Classification, `\`, "")))
		}
	} else if technologyStatisticExists != nil {
		for _, t := range technologyStatisticExists {
			for _, tag := range t.Tag {
				tags = append(tags, regexp.MustCompile(tag.Name))
				for foundTag, _ := range foundTags {
					// The test checks for a prefix that's an attr on the techonology-statistic-exist and that it has a suffix which is the name of a technology
					if strings.HasPrefix(foundTag, tag.Name) && strings.HasSuffix(foundTag, t.Name) {
						numFound += 1
					}
				}
			}
		}
		return numFound >= matchesRequired, numFound, matchesRequired
	} else if technologyTagExists != nil {
		for _, t := range technologyTagExists {
			tags = append(tags, regexp.MustCompile(t.Technologytag))
		}
	}

	if len(tags) != 0 {
		for _, tag := range tags {
			for foundTag, _ := range foundTags {
				if tag.MatchString(foundTag) {
					numFound += 1
				}
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
