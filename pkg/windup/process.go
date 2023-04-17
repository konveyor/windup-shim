package windup

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
)

func ProcessWindupRuleset(path string) *Ruleset {
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
	var ruleset Ruleset

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

func ProcessWindupRuletest(path string) *Ruletest {
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
	var ruletest Ruletest
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
