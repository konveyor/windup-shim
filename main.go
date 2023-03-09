package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
	"gopkg.in/yaml.v2"
)

func main() {
	var outputDir, data string
	convertCmd := flag.NewFlagSet("convert", flag.ExitOnError)
	convertCmd.StringVar(&outputDir, "outputdir", "analyzer-lsp-rules", "The output location for converted rules")
	testCmd := flag.NewFlagSet("test", flag.ExitOnError)
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
				fmt.Println("The location of one or more windup XML files is required")
				return
			}
			for _, location := range testCmd.Args() {
				rulesets := []windup.Ruleset{}
				ruletests := []windup.Ruletest{}
				err := filepath.WalkDir(location, walkXML(location, &rulesets, &ruletests, false))
				if err != nil {
					fmt.Println(err)
				}
				for _, test := range ruletests {
					err := executeTest(test, location)
					if err != nil {
						fmt.Println(err)
					}
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
			output, err := executeRulesets(rulesets, data)
			fmt.Println(output, err)
		}
	default:
		fmt.Println(help)
	}
}

func executeRulesets(rulesets []windup.Ruleset, datadir string) (string, error) {
	datadir, err := filepath.Abs(datadir)
	if err != nil {
		return "", err
	}
	sourceFiles := []string{}
	converted := [][]map[string]interface{}{}
	for _, ruleset := range rulesets {
		sourceFiles = append(sourceFiles, ruleset.SourceFile)
		converted = append(converted, convertWindupRulesetToAnalyzer(ruleset))
	}
	dir, err := os.MkdirTemp("", "analyzer-lsp")
	if err != nil {
		return "", err
	}
	os.Mkdir(filepath.Join(dir, "rules"), os.ModePerm)
	fmt.Println(dir)
	// write ruleset to disk
	for i, ruleset := range converted {
		path := filepath.Join(dir, "rules", strconv.Itoa(i)+".yaml")
		err = writeYAML(ruleset, path)
		if err != nil {
			return "", err
		}
	}
	err = writeYAML(map[string]interface{}{"name": "test-ruleset"}, filepath.Join(dir, "rules", "ruleset.yaml"))
	if err != nil {
		return "", err
	}
	// Template config file for analyzer
	providerConfig := []map[string]interface{}{
		map[string]interface{}{
			"name":           "java",
			"location":       datadir,
			"binaryLocation": "/jdtls/bin/jdtls",
			"providerSpecificConfig": map[string]string{
				"bundles": "/jdtls/java-analyzer-bundle/java-analyzer-bundle.core/target/java-analyzer-bundle.core-1.0.0-SNAPSHOT.jar",
			},
		},
		{
			"name":     "builtin",
			"location": datadir,
		},
	}
	err = writeJSON(providerConfig, filepath.Join(dir, "provider_config.json"))
	if err != nil {
		return "", err
	}
	// TODO now that directory is setup, need to execute
	//	analyzer-lsp -provider-settings $dir/provider_config.json -rules $dir/rules
	// and capture the output
	args := []string{"-provider-settings", filepath.Join(dir, "/provider_config.json"), "-rules", filepath.Join(dir, "rules")}
	debugCmd := strings.Join(append([]string{"dlv debug /analyzer-lsp/main.go --"}, args...), " ")
	cmd := exec.Command("konveyor-analyzer", args...)
	debugInfo := map[string]interface{}{
		"debugCmd":   debugCmd,
		"cmd":        strings.Join(append([]string{"konveyor-analyzer"}, args...), " "),
		"sourceFile": sourceFiles,
	}
	writeYAML(debugInfo, filepath.Join(dir, "debug.yaml"))
	stdout, err := cmd.Output()
	debugInfo["err"] = err
	debugInfo["output"] = string(stdout)
	writeYAML(debugInfo, filepath.Join(dir, "debug.yaml"))

	return string(stdout), err
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

func executeTest(test windup.Ruletest, location string) error {
	rulesets := []windup.Ruleset{}
	for _, path := range test.RulePath {
		ruleset := processWindupRuleset(path)
		if ruleset != nil {
			rulesets = append(rulesets, *ruleset)
		}
	}
	output, err := executeRulesets(rulesets, test.TestDataPath)
	fmt.Println(output, err)
	return err
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
			for k, v := range perform {
				rule[k] = v
			}
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
	dependency := map[string]interface{}{
		"name": strings.Replace(strings.Join([]string{windupDependency.GroupId, windupDependency.ArtifactId}, "."), "{*}", "*", -1),
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

func convertWindupWhenToAnalyzer(windupWhen windup.When, where map[string]string) []map[string]interface{} {
	// TODO Rule.When
	// TODO - Graphquery
	conditions := []map[string]interface{}{}
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
				// TODO this is probably a dumb assumption
				condition["ignore"] = true
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
						// TODO this is probably a dumb assumption
						condition["ignore"] = true
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
					// TODO this is probably a dumb assumption
					condition["ignore"] = true
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
					matches = strings.Replace(matches, "/"+ns.Prefix+":", "/", -1)
				}
			}
			xmlCond := map[string]interface{}{
				"xpath": matches,
			}
			// TODO We don't support regexes here, may need to break it out into a separate lookup that gets passed through
			if xf.In != "" {
				xmlCond["filepaths"] = []string{xf.In}
			}
			condition := map[string]interface{}{
				"builtin.xml": xmlCond,
			}
			if xf.As != "" {
				condition["as"] = xf.As
				// TODO this is probably a dumb assumption
				condition["ignore"] = true
			}
			if xf.From != "" {
				condition["from"] = xf.From
			}
			conditions = append(conditions, condition)
		}
	}

	if windupWhen.File != nil {
		for _, f := range windupWhen.File {
			condition := map[string]interface{}{
				"builtin.file": strings.Replace(f.Filename, "{*}", "*", -1),
			}
			if f.As != "" {
				condition["as"] = f.As
				// TODO this is probably a dumb assumption
				condition["ignore"] = true
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
				"builtin.file": strings.Replace(f.Filename, "{*}", "*", -1),
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
		cleaned := strings.Trim(line, "\n \t")
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
		ret := map[string]interface{}{}
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
			ret["message"] = trimMessage(hint.Message)
		}
	}
	if perform.Technologyidentified != nil {
		for _, ti := range perform.Technologyidentified {
			for _, tag := range ti.Tag {
				tags = append(tags, tag.Name)
			}
			if ti.Name != "" {
				// TODO what do we want to do with this?
				tags = append(tags, ti.Name)
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

	ret["tags"] = tags
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
		// TODO parse tests as well
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
		// TODO parse tests as well
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
