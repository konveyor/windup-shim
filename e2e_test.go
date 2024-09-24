package main

import (
	"fmt"
	"github.com/konveyor/windup-shim/pkg/conversion"
	"github.com/konveyor/windup-shim/pkg/windup"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func Test_convertRule(t *testing.T) {

	rulesets := []windup.Ruleset{}
	ruleTests := []windup.Ruletest{}

	err := filepath.WalkDir("./data", WalkXML("./data/test-ruleset.xml", &rulesets, &ruleTests, false))
	if err != nil {
		fmt.Println(err)
	}
	_, err = conversion.ConvertWindupRulesetsToAnalyzer(rulesets, "./data/test-ruleset.xml", "./test-rule-output", true, false)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll("./test-rule-output")
		if err != nil {
			t.Fatalf("Failed to remove output directory %v", err)
		}
	}()

	expected, err := os.ReadFile("./data/test_rule.yaml")
	if err != nil {
		t.Fatalf("Failed to read the original yaml: %v", err)
	}

	output, err := os.ReadFile("./test-rule-output/data/01-test-rule.yaml")
	if err != nil {
		t.Fatalf("Failed to read the output yaml: %v", err)
	}

	if string(expected) != string(output) {
		t.Fatalf("YAML files do not match\nExpected: %v\nGot: %v", string(expected), string(output))
	}
}
