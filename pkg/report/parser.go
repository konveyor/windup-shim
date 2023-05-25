package report

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/konveyor/analyzer-lsp/hubapi"
	"go.lsp.dev/uri"
	"gopkg.in/yaml.v2"
)

// unmarshalReportFile
func unmarshalReportFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(data, v)
		if err != nil {
			return err
		}
	} else {
		err = yaml.Unmarshal(data, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// ParseFileContentJson parses json file at path as FileContent
func ParseFileContentJson(path string) (FileContent, error) {
	file := FileContent{}
	err := unmarshalReportFile(path, &file)
	if err != nil {
		return file, err
	}
	return file, nil
}

// ParseFilesJson parses ./api/files.json at basePath
func ParseFilesJson(basePath string) ([]File, error) {
	files := []File{}
	err := unmarshalReportFile(
		filepath.Join(basePath, "api", "files.json"), &files)
	if err != nil {
		return files, err
	}
	for idx := range files {
		file := &files[idx]
		contentPath := filepath.Join(basePath, "api", "files", fmt.Sprintf("%s.json", file.ID))
		content, err := ParseFileContentJson(contentPath)
		if err != nil {
			log.Printf("failed parsing file %s\n", contentPath)
		}
		file.Content = content
	}
	return files, nil
}

// ParseIssuesJson parses ./api/issues.json at basePath
func ParseIssuesJson(basePath string) (Issues, error) {
	path := filepath.Join(basePath, "api", "issues.json")
	// issues.json file has reports for multiple apps
	reports := []struct {
		ApplicationId string `json:"applicationId,omitempty"`
		// map of issues Category -> []Issue
		Issues map[string][]Issue `json:"issues,omitempty"`
	}{}
	err := unmarshalReportFile(path, &reports)
	if err != nil {
		return nil, err
	}
	filesMap, err := loadFiles(basePath)
	if err != nil {
		return nil, err
	}
	issues := make(Issues)
	for _, report := range reports {
		if report.ApplicationId == "" {
			continue
		}
		for category, issueList := range report.Issues {
			for idx := range issueList {
				issue := &issueList[idx]
				issue.Category = category
				for _, affectedFile := range issue.AffectedFiles {
					for jdx := range affectedFile.FileRefs {
						fileRef := &affectedFile.FileRefs[jdx]
						if val, ok := filesMap[fileRef.FileID]; ok {
							fileRef.File = val
							fileRef.File.Hints = filterHintsByRuleIdAndMessage(
								issue.RuleID, affectedFile.Description, fileRef.File.Hints)
						}
					}
				}
				if existingIssue, ok := issues[issue.RuleID]; !ok {
					issues[issue.RuleID] = issue
				} else {
					existingIssue.AffectedFiles = append(existingIssue.AffectedFiles, issue.AffectedFiles...)
					existingIssue.TotalIncidents += issue.TotalIncidents
					existingIssue.TotalStoryPoints += issue.TotalStoryPoints
				}
			}
		}
	}
	return issues, nil
}

func ParseViolations(path string) (hubapi.RuleSet, error) {
	rs := hubapi.RuleSet{
		Name:       "konveyor-analyzer",
		Tags:       []string{},
		Violations: map[string]hubapi.Violation{},
	}
	rulesets := []hubapi.RuleSet{}
	err := unmarshalReportFile(path, &rulesets)
	if err != nil {
		return rs, err
	}
	for _, ruleset := range rulesets {
		dedupTags := map[string]bool{}
		for _, tag := range ruleset.Tags {
			if _, ok := dedupTags[tag]; !ok {
				rs.Tags = append(rs.Tags, tag)
				dedupTags[tag] = true
			}
		}
		for ruleId, violation := range ruleset.Violations {
			rs.Violations[ruleId] = violation
		}
	}
	return rs, nil
}

func (i Issues) AsRuleset() hubapi.RuleSet {
	rs := hubapi.RuleSet{
		Tags: []string{},
	}
	violations := map[string]hubapi.Violation{}
	dedupTags := map[string]bool{}
	for ruleId, issue := range i {
		ruleId = mappedRuleId(ruleId)
		violation, tags := issue.AsViolationAndTags()
		// only create incidents for non tagging rules
		if len(violation.Incidents) != 0 {
			violations[ruleId] = violation
		} else {
			if _, ok := dedupTags[issue.Name]; !ok {
				rs.Tags = append(rs.Tags, issue.Name)
			}
		}
		for _, tag := range tags {
			if _, ok := dedupTags[tag]; !ok {
				rs.Tags = append(rs.Tags, tag)
				dedupTags[tag] = true
			}
		}
	}
	rs.Violations = violations
	return rs
}

func (i Issue) AsViolationAndTags() (hubapi.Violation, []string) {
	tags := []string{}
	violation := hubapi.Violation{
		Description: "",
		Category:    toAnalyzerCategory(i.Category),
		Effort:      &i.Effort.Points,
		Incidents:   []hubapi.Incident{},
		Links:       []hubapi.Link{},
	}
	for _, affFile := range i.AffectedFiles {
		incidents, hintTags := affFile.AsIncidentsAndTags()
		violation.Incidents = append(violation.Incidents,
			incidents...)
		tags = append(tags, hintTags...)
		dedupLinks := map[string]bool{}
		for _, ref := range affFile.FileRefs {
			for _, hint := range ref.File.Hints {
				for _, link := range hint.Links {
					if _, ok := dedupLinks[link.Href]; !ok {
						violation.Links = append(violation.Links,
							hubapi.Link{URL: link.Href, Title: link.Title})
						dedupLinks[link.Href] = true
					}

				}
			}
		}
	}
	return violation, tags
}

func (a AffectedFile) AsIncidentsAndTags() ([]hubapi.Incident, []string) {
	incidents := []hubapi.Incident{}
	tags := []string{}
	dedupTags := map[string]bool{}
	for _, fileRef := range a.FileRefs {
		// only find matching incidents
		incidents = append(incidents,
			filterIncidentsForMessage(a.Description, fileRef.AsIncidents())...)
		// Get tags
		for _, windupTag := range fileRef.File.Tags {
			tag := windupTag.Name
			if _, ok := dedupTags[tag]; !ok {
				tags = append(tags, tag)
				dedupTags[tag] = true
			}
		}
	}
	return incidents, tags
}

func (f FileRef) AsIncidents() []hubapi.Incident {
	// dedup line numbers
	dedupLineNo := map[int]bool{}
	incidents := []hubapi.Incident{}
	for _, hint := range f.File.Hints {
		if _, ok := dedupLineNo[hint.Line]; !ok {
			incidents = append(incidents, hubapi.Incident{
				URI:      uri.URI(f.File.FullPath),
				Message:  hint.Content,
				CodeSnip: f.File.Content.Content,
				Variables: map[string]interface{}{
					"lineNumber": hint.Line,
				},
			})
			dedupLineNo[hint.Line] = true
		}
	}
	return incidents
}

// returns FileId -> File
func loadFiles(basePath string) (map[string]File, error) {
	files, err := ParseFilesJson(basePath)
	if err != nil {
		return nil, err
	}
	filesMap := map[string]File{}
	for _, file := range files {
		filesMap[file.ID] = file
	}
	return filesMap, nil
}

func toAnalyzerCategory(windupCat string) *hubapi.Category {
	switch windupCat {
	case "mandatory", "cloud-mandatory":
		return &hubapi.Mandatory
	case "optional", "cloud-optional":
		return &hubapi.Optional
	case "potential":
		return &hubapi.Potential
	default:
		return &hubapi.Potential
	}
}

func filterIncidentsForMessage(msg string, incidents []hubapi.Incident) []hubapi.Incident {
	filtered := []hubapi.Incident{}
	for _, inc := range incidents {
		if inc.Message == msg {
			filtered = append(filtered, inc)
		}
	}
	return filtered
}

func filterHintsByRuleIdAndMessage(ruleId string, message string, hints []Hint) []Hint {
	filtered := []Hint{}
	for _, hint := range hints {
		if hint.RuleID != ruleId || hint.Content != message {
			continue
		}
		filtered = append(filtered, hint)
	}
	return filtered
}

func mappedRuleId(orig string) string {
	switch orig {
	case "DiscoverHardcodedIPAddressRuleProvider":
		return "hardcoded-ip-address"
	default:
		return orig
	}

}
