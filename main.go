package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fabianvf/windup-rulesets-yaml/pkg/conversion"
	"github.com/fabianvf/windup-rulesets-yaml/pkg/execution"
	"github.com/fabianvf/windup-rulesets-yaml/pkg/report"
	"github.com/fabianvf/windup-rulesets-yaml/pkg/windup"
)

func main() {
	var outputDir, data, appPath, targets string
	var failFast, flattenRulesets bool
	convertCmd := flag.NewFlagSet("convert", flag.ExitOnError)
	convertCmd.StringVar(&outputDir, "outputdir", "analyzer-lsp-rules", "The output location for converted rules")
	convertCmd.BoolVar(&flattenRulesets, "flatten", true, "Preserve original ruleset structure of windup rules")
	testCmd := flag.NewFlagSet("test", flag.ExitOnError)
	testCmd.BoolVar(&failFast, "fail-fast", false, "If true, fail on first test failure")
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runCmd.StringVar(&data, "data", "", "The location of the source code to run the rules against")
	reportTestCmd := flag.NewFlagSet("report-test", flag.ExitOnError)
	reportTestCmd.StringVar(&appPath, "app", "/example-applications/example-1/", "Example application to run the test on")
	reportTestCmd.StringVar(&targets, "targets", "cloud-readiness", "Comma separated list of targets")
	help := "Supported subcommands are convert, run, test and report-test"
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
				_, err = conversion.ConvertWindupRulesetsToAnalyzer(rulesets, location, outputDir, flattenRulesets, false)
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
					successes, total, err := execution.ExecuteTest(test, location, true)
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
				output, dir, err := execution.ExecuteRulesets(rulesets, location, data, false)
				fmt.Println(output, dir, err)
			}
		}
	case "report-test":
		if err := reportTestCmd.Parse(os.Args[2:]); err == nil {
			if appPath == "" {
				log.Fatal("Path to an application to analyze must be specified '-app option'")
			}
			if targets == "" {
				log.Fatal("At least one target is required '--targets'")
			}
			tmpDir, err := os.MkdirTemp("", "shim-workdir")
			if err != nil {
				log.Fatalf("failed creating temp dir - %v", err)
			}
			windupOutputPath := filepath.Join(tmpDir, "windup-report")
			analyzerOutputPath := filepath.Join(tmpDir, "analyzer-output.yaml")
			windupCmd := execution.WindupCmd{
				Command: execution.Command{
					BinPath: "/usr/bin/windup-cli",
					Env: []string{
						"JAVA_HOME=/java-11-openjdk",
						"JAVA_VERSION=11",
					},
					OutputPath:     windupOutputPath,
					SourceCodePath: appPath,
					WorkDirPath:    tmpDir,
					Targets:        strings.Split(targets, ","),
				},
				SourceMode: true,
				WithDeps:   true,
			}
			err = windupCmd.Run()
			if err != nil {
				log.Fatalf("failed running windup - %v", err)
			}
			analyzerCmd := execution.AnalyzerCmd{
				Command: execution.Command{
					BinPath:        "/usr/bin/konveyor-analyzer",
					OutputPath:     analyzerOutputPath,
					SourceCodePath: appPath,
					WorkDirPath:    tmpDir,
					Targets:        strings.Split(targets, ","),
				},
				RulesPath:     "/rules/",
				LabelSelector: "technology-usage || discovery",
			}
			err = analyzerCmd.Run()
			if err != nil {
				log.Fatalf("failed running analyzer - %v", err)
			}
			ruleset, err := report.ParseViolations(analyzerOutputPath)
			if err != nil {
				log.Fatalf("failed to parse analyzer report at %s", analyzerOutputPath)
			}
			windupIssues, err := report.ParseIssuesJson(windupOutputPath)
			if err != nil {
				log.Fatalf("failed to parse windup report at %s", windupOutputPath)
			}
			result := report.CompareRuleset(windupIssues.AsRuleset(), ruleset)
			log.Println(result.String())
		}
	default:
		fmt.Println(help)
	}
}

func walkXML(root string, rulesets *[]windup.Ruleset, ruletests *[]windup.Ruletest, writeYAML bool) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if !strings.HasSuffix(path, ".xml") {
			// fmt.Printf("Skipping %s because it is not a ruleset\n", path)
			return nil
		}
		if strings.HasSuffix(path, ".test.xml") && ruletests != nil {
			ruletest := windup.ProcessWindupRuletest(path)
			if ruletest != nil {
				*ruletests = append(*ruletests, *ruletest)
			}
		} else if rulesets != nil {
			ruleset := windup.ProcessWindupRuleset(path)
			if ruleset != nil {
				*rulesets = append(*rulesets, *ruleset)
			}
		}
		return err
	}
}
