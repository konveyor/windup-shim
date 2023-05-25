package report

// Issues is a map of RuleID -> Issue
type Issues map[string]*Issue

// Issue is what we see in each row in windup output
type Issue struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	RuleID             string         `json:"ruleId"`
	Category           string         `json:"category"`
	Effort             Effort         `json:"effort"`
	TotalIncidents     int            `json:"totalIncidents"`
	TotalStoryPoints   int            `json:"totalStoryPoints"`
	Links              []interface{}  `json:"links"`
	AffectedFiles      []AffectedFile `json:"affectedFiles"`
	SourceTechnologies []string       `json:"sourceTechnologies"`
	TargetTechnologies []string       `json:"targetTechnologies"`
}

type Effort struct {
	Type        string `json:"type"`
	Points      int    `json:"points"`
	Description string `json:"description"`
}

// AffectedFile is a set of incidents found in a file
type AffectedFile struct {
	Description string    `json:"description"`
	FileRefs    []FileRef `json:"files"`
}

// FileRef is a reference to a file model
type FileRef struct {
	FileID      string `json:"fileId"`
	FileName    string `json:"fileName"`
	Occurrences int    `json:"occurrences"`
	File        File   `json:"file"`
}

// File defines a file. it has content of the file and
// hints & tags to display when its opened in the UI
type File struct {
	ID                          string        `json:"id"`
	FullPath                    string        `json:"fullPath"`
	PrettyPath                  string        `json:"prettyPath"`
	PrettyFileName              string        `json:"prettyFileName"`
	SourceType                  string        `json:"sourceType"`
	StoryPoints                 int           `json:"storyPoints"`
	Hints                       []Hint        `json:"hints"`
	Tags                        []FileTag     `json:"tags"`
	ClassificationsAndHintsTags []interface{} `json:"classificationsAndHintsTags"`
	Content                     FileContent   `json:"fileContent"`
}

// Hint is closely equivalent to a message in violations
type Hint struct {
	Line    int    `json:"line"`
	Title   string `json:"title"`
	RuleID  string `json:"ruleId"`
	Content string `json:"content"`
	Links   []Link `json:"links"`
}

type Link struct {
	Title string `json:"title"`
	Href  string `json:"href"`
}

// FileTag is a tag displayed for a file
type FileTag struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Level   string `json:"level"`
}

// FileContent has the actual file content in it
type FileContent struct {
	Id      string `json:"id"`
	Content string `json:"content"`
}
