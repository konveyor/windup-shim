package windup

type Addon struct {
	Id string `xml:"id,attr,omitempty" yaml:"id,omitempty"`
}

type Annotationlist struct {
	// 1 rule (rules-reviewed/eap7/eap6/hsearch.windup.xml)
	Annotationtype *Annotationtype `xml:"annotation-type,omitempty" yaml:"annotation-type,omitempty"`
	// 0 rules
	Annotationlist *Annotationlist `xml:"annotation-list,omitempty" yaml:"annotation-list,omitempty"`
	// 5 rules
	Annotationliteral *Annotationliteral `xml:"annotation-literal,omitempty" yaml:"annotation-literal,omitempty"`
	Name              string             `xml:"name,attr,omitempty" yaml:"name,omitempty"`
	Index             int                `xml:"index,attr,omitempty" yaml:"index,omitempty"`
}

type Annotationliteral struct {
	Name    string `xml:"name,attr,omitempty" yaml:"name,omitempty"`
	Pattern string `xml:"pattern,attr,omitempty" yaml:"pattern,omitempty"`
}

type Annotationtype struct {
	Annotationtype    *Annotationtype    `xml:"annotation-type,omitempty" yaml:"annotation-type,omitempty"`
	Annotationlist    *Annotationlist    `xml:"annotation-list,omitempty" yaml:"annotation-list,omitempty"`
	Annotationliteral *Annotationliteral `xml:"annotation-literal,omitempty" yaml:"annotation-literal,omitempty"`
	Name              string             `xml:"name,attr,omitempty" yaml:"name,omitempty"`
	Pattern           string             `xml:"pattern,attr,omitempty" yaml:"pattern,omitempty"`
}

type Categoryidtype string

type Classification struct {
	Description      []string             `xml:"description,omitempty" yaml:"description,omitempty"`
	Link             []Link               `xml:"link,omitempty" yaml:"link,omitempty"`
	Tag              []string             `xml:"tag,omitempty" yaml:"tag,omitempty"`
	Quickfix         []Quickfix           `xml:"quickfix,omitempty" yaml:"quickfix,omitempty"`
	Title            string               `xml:"title,attr" yaml:"title"`
	Effort           byte                 `xml:"effort,attr,omitempty" yaml:"effort,omitempty"`
	Categoryid       string               `xml:"category-id,attr,omitempty" yaml:"category-id,omitempty"`
	Issuedisplaymode Issuedisplaymodetype `xml:"issue-display-mode,attr,omitempty" yaml:"issue-display-mode,omitempty"`
	Of               string               `xml:"of,attr,omitempty" yaml:"of,omitempty"`
}

type Classificationexists struct {
	Classification string `xml:"classification,attr" yaml:"classification"`
	In             string `xml:"in,attr,omitempty" yaml:"in,omitempty"`
}

type Dependencies struct {
	Addon []Addon `xml:"addon" yaml:"addon"`
}

type Dependency struct {
	GroupId     string `xml:"groupId,attr,omitempty" yaml:"groupId,omitempty"`
	ArtifactId  string `xml:"artifactId,attr,omitempty" yaml:"artifactId,omitempty"`
	FromVersion string `xml:"fromVersion,attr,omitempty" yaml:"fromVersion,omitempty"`
	ToVersion   string `xml:"toVersion,attr,omitempty" yaml:"toVersion,omitempty"`
}

type Fail struct {
	Message string `xml:"message,attr,omitempty" yaml:"message,omitempty"`
}

type File struct {
	From     string `xml:"from,attr,omitempty" yaml:"from,omitempty"`
	Filename string `xml:"filename,attr" yaml:"filename"`
	As       string `xml:"as,attr,omitempty" yaml:"as,omitempty"`
}

type Filecontent struct {
	From     string `xml:"from,attr,omitempty" yaml:"from,omitempty"`
	Pattern  string `xml:"pattern,attr" yaml:"pattern"`
	Filename string `xml:"filename,attr,omitempty" yaml:"filename,omitempty"`
	As       string `xml:"as,attr,omitempty" yaml:"as,omitempty"`
}

type Fileexists struct {
	Filename string `xml:"filename,attr" yaml:"filename"`
}

type Graphquery struct {
	Property      Property `xml:"property" yaml:"property"`
	Discriminator string   `xml:"discriminator,attr" yaml:"discriminator"`
	From          string   `xml:"from,attr,omitempty" yaml:"from,omitempty"`
	As            string   `xml:"as,attr,omitempty" yaml:"as,omitempty"`
}

type Hasclassification struct {
	Title string `xml:"title,attr,omitempty" yaml:"title,omitempty"`
}

type Hashint struct {
	Message string `xml:"message,attr,omitempty" yaml:"message,omitempty"`
}

type Hint struct {
	Message          string               `xml:"message,omitempty" yaml:"message,omitempty"`
	Link             []Link               `xml:"link,omitempty" yaml:"link,omitempty"`
	Tag              []string             `xml:"tag,omitempty" yaml:"tag,omitempty"`
	Quickfix         []Quickfix           `xml:"quickfix,omitempty" yaml:"quickfix,omitempty"`
	Title            string               `xml:"title,attr" yaml:"title"`
	Categoryid       string               `xml:"category-id,attr,omitempty" yaml:"category-id,omitempty"`
	Issuedisplaymode Issuedisplaymodetype `xml:"issue-display-mode,attr,omitempty" yaml:"issue-display-mode,omitempty"`
	In               string               `xml:"in,attr,omitempty" yaml:"in,omitempty"`
	Effort           byte                 `xml:"effort,attr,omitempty" yaml:"effort,omitempty"`
	MessageAttr      string               `xml:"message,attr,omitempty" yaml:"messageAttr,omitempty"`
}

type Hintexists struct {
	Message string `xml:"message,attr" yaml:"message"`
	In      string `xml:"in,attr,omitempty" yaml:"in,omitempty"`
}

// May be one of detail-only, all
type Issuedisplaymodetype string

type Iterablefilter struct {
	True                       string                 `xml:"true,omitempty" yaml:"true,omitempty"`
	False                      string                 `xml:"false,omitempty" yaml:"false,omitempty"`
	Javaclass                  []Javaclass            `xml:"javaclass,omitempty" yaml:"javaclass,omitempty"`
	Xmlfile                    []Xmlfile              `xml:"xmlfile,omitempty" yaml:"xmlfile,omitempty"`
	Project                    []Project              `xml:"project,omitempty" yaml:"project,omitempty"`
	Filecontent                []Filecontent          `xml:"filecontent,omitempty" yaml:"filecontent,omitempty"`
	File                       []File                 `xml:"file,omitempty" yaml:"file,omitempty"`
	Classificationexists       []Classificationexists `xml:"classification-exists,omitempty" yaml:"classification-exists,omitempty"`
	Fileexists                 []Fileexists           `xml:"file-exists,omitempty" yaml:"file-exists,omitempty"`
	Hintexists                 []Hintexists           `xml:"hint-exists,omitempty" yaml:"hint-exists,omitempty"`
	Lineitemexists             []Lineitemexists       `xml:"lineitem-exists,omitempty" yaml:"lineitem-exists,omitempty"`
	Technologystatisticsexists []Technologyidentified `xml:"technology-statistics-exists,omitempty" yaml:"technology-statistics-exists,omitempty"`
	Iterablefilter             []Iterablefilter       `xml:"iterable-filter,omitempty" yaml:"iterable-filter,omitempty"`
	Tofilemodel                []Whenbase             `xml:"to-file-model,omitempty" yaml:"to-file-model,omitempty"`
	Graphquery                 []Graphquery           `xml:"graph-query,omitempty" yaml:"graph-query,omitempty"`
	Technologytagexists        []Technologytagexists  `xml:"technology-tag-exists,omitempty" yaml:"technology-tag-exists,omitempty"`
	Dependency                 []Dependency           `xml:"dependency,omitempty" yaml:"dependency,omitempty"`
	Size                       int                    `xml:"size,attr,omitempty" yaml:"size,omitempty"`
}

type Iteration struct {
	When                 Iterationwhen          `xml:"when,omitempty" yaml:"when,omitempty"`
	Perform              *Iteration             `xml:"perform,omitempty" yaml:"perform,omitempty"`
	Otherwise            *Iteration             `xml:"otherwise,omitempty" yaml:"otherwise,omitempty"`
	Iteration            []Iteration            `xml:"iteration,omitempty" yaml:"iteration,omitempty"`
	Classification       []Classification       `xml:"classification,omitempty" yaml:"classification,omitempty"`
	Hint                 []Hint                 `xml:"hint,omitempty" yaml:"hint,omitempty"`
	Log                  []Log                  `xml:"log,omitempty" yaml:"log,omitempty"`
	Xslt                 []Xslt                 `xml:"xslt,omitempty" yaml:"xslt,omitempty"`
	Lineitem             []Lineitem             `xml:"lineitem,omitempty" yaml:"lineitem,omitempty"`
	Fail                 []Fail                 `xml:"fail,omitempty" yaml:"fail,omitempty"`
	Classificationexists []Classificationexists `xml:"classification-exists,omitempty" yaml:"classification-exists,omitempty"`
	Fileexists           []Fileexists           `xml:"file-exists,omitempty" yaml:"file-exists,omitempty"`
	Hintexists           []Hintexists           `xml:"hint-exists,omitempty" yaml:"hint-exists,omitempty"`
	Lineitemexists       []Lineitemexists       `xml:"lineitem-exists,omitempty" yaml:"lineitem-exists,omitempty"`
	Technologyidentified []Technologyidentified `xml:"technology-identified,omitempty" yaml:"technology-identified,omitempty"`
	Technologytag        []Technologytag        `xml:"technology-tag,omitempty" yaml:"technology-tag,omitempty"`
	Over                 string                 `xml:"over,attr,omitempty" yaml:"over,omitempty"`
}

type Iterationwhen struct {
	True                       string                 `xml:"true,omitempty" yaml:"true,omitempty"`
	False                      string                 `xml:"false,omitempty" yaml:"false,omitempty"`
	Javaclass                  []Javaclass            `xml:"javaclass,omitempty" yaml:"javaclass,omitempty"`
	Xmlfile                    []Xmlfile              `xml:"xmlfile,omitempty" yaml:"xmlfile,omitempty"`
	Project                    []Project              `xml:"project,omitempty" yaml:"project,omitempty"`
	Filecontent                []Filecontent          `xml:"filecontent,omitempty" yaml:"filecontent,omitempty"`
	File                       []File                 `xml:"file,omitempty" yaml:"file,omitempty"`
	Classificationexists       []Classificationexists `xml:"classification-exists,omitempty" yaml:"classification-exists,omitempty"`
	Fileexists                 []Fileexists           `xml:"file-exists,omitempty" yaml:"file-exists,omitempty"`
	Hintexists                 []Hintexists           `xml:"hint-exists,omitempty" yaml:"hint-exists,omitempty"`
	Lineitemexists             []Lineitemexists       `xml:"lineitem-exists,omitempty" yaml:"lineitem-exists,omitempty"`
	Technologystatisticsexists []Technologyidentified `xml:"technology-statistics-exists,omitempty" yaml:"technology-statistics-exists,omitempty"`
	Iterablefilter             []Iterablefilter       `xml:"iterable-filter,omitempty" yaml:"iterable-filter,omitempty"`
	Tofilemodel                []Whenbase             `xml:"to-file-model,omitempty" yaml:"to-file-model,omitempty"`
	Graphquery                 []Graphquery           `xml:"graph-query,omitempty" yaml:"graph-query,omitempty"`
	Technologytagexists        []Technologytagexists  `xml:"technology-tag-exists,omitempty" yaml:"technology-tag-exists,omitempty"`
	Dependency                 []Dependency           `xml:"dependency,omitempty" yaml:"dependency,omitempty"`
	Hasclassification          Hasclassification      `xml:"has-classification,omitempty" yaml:"has-classification,omitempty"`
	Hashint                    Hashint                `xml:"has-hint,omitempty" yaml:"has-hint,omitempty"`
	Or                         []When                 `xml:"or,omitempty" yaml:"or,omitempty"`
	And                        []When                 `xml:"and,omitempty" yaml:"and,omitempty"`
	Not                        []When                 `xml:"not,omitempty" yaml:"not,omitempty"`
}

type Javaclass struct {
	Location          []string          `xml:"location,omitempty" yaml:"location,omitempty"`
	Annotationtype    Annotationtype    `xml:"annotation-type,omitempty" yaml:"annotation-type,omitempty"`
	Annotationlist    Annotationlist    `xml:"annotation-list,omitempty" yaml:"annotation-list,omitempty"`
	Annotationliteral Annotationliteral `xml:"annotation-literal,omitempty" yaml:"annotation-literal,omitempty"`
	References        string            `xml:"references,attr,omitempty" yaml:"references,omitempty"`
	MatchesSource     string            `xml:"matchesSource,attr,omitempty" yaml:"matchesSource,omitempty"`
	As                string            `xml:"as,attr,omitempty" yaml:"as,omitempty"`
	From              string            `xml:"from,attr,omitempty" yaml:"from,omitempty"`
	In                string            `xml:"in,attr,omitempty" yaml:"in,omitempty"`
}

type Javaclassignore struct {
	Referenceprefix string `xml:"reference-prefix,attr" yaml:"reference-prefix"`
}

type Lineitem struct {
	Value   string `xml:",chardata" yaml:"value"`
	Message string `xml:"message,attr" yaml:"message"`
}

type Lineitemexists struct {
	Message string `xml:"message,attr" yaml:"message"`
}

type Link struct {
	Value string `xml:",chardata" yaml:"value"`
	Title string `xml:"title,attr" yaml:"title"`
	HRef  string `xml:"href,attr" yaml:"href"`
}

type Log struct {
	Message string `xml:"message,attr,omitempty" yaml:"message,omitempty"`
}

type Mapping struct {
	From         string           `xml:"from,attr" yaml:"from"`
	To           string           `xml:"to,attr" yaml:"to"`
	OnParseError OnParseErrortype `xml:"onParseError,attr,omitempty" yaml:"onParseError,omitempty"`
}

type Matches struct {
	Value   string `xml:",chardata" yaml:"value"`
	Pattern string `xml:"pattern,attr,omitempty" yaml:"pattern,omitempty"`
}

type Metadata struct {
	Description      string       `xml:"description,omitempty" yaml:"description,omitempty"`
	Dependencies     Dependencies `xml:"dependencies" yaml:"dependencies"`
	SourceTechnology []Technology `xml:"sourceTechnology,omitempty" yaml:"sourceTechnology,omitempty"`
	TargetTechnology []Technology `xml:"targetTechnology,omitempty" yaml:"targetTechnology,omitempty"`
	Phase            Phase        `xml:"phase,omitempty" yaml:"phase,omitempty"`
	ExecuteAfter     []string     `xml:"executeAfter,omitempty" yaml:"executeAfter,omitempty"`
	ExecuteBefore    []string     `xml:"executeBefore,omitempty" yaml:"executeBefore,omitempty"`
	Tag              []string     `xml:"tag,omitempty" yaml:"tag,omitempty"`
	OverrideRules    bool         `xml:"overrideRules,omitempty" yaml:"overrideRules,omitempty"`
}

type Namespace struct {
	Value  string `xml:",chardata" yaml:"value"`
	Prefix string `xml:"prefix,attr,omitempty" yaml:"prefix,omitempty"`
	Uri    string `xml:"uri,attr,omitempty" yaml:"uri,omitempty"`
}

// May be one of ignore, warn
type OnParseErrortype string

// May be one of InitialAnalysisPhase, MigrationRulesPhase, PostMigrationRulesPhase, PreReportGenerationPhase
type Phase string

type Project struct {
	Artifact Dependency `xml:"artifact" yaml:"artifact"`
}

type Property struct {
	Name       string             `xml:"name,attr" yaml:"name"`
	Type       Propertytype       `xml:"type,attr,omitempty" yaml:"type,omitempty"`
	SearchType Propertysearchtype `xml:"searchType,attr,omitempty" yaml:"searchType,omitempty"`
}

// May be one of regex, equals
type Propertysearchtype string

// May be one of STRING, BOOLEAN
type Propertytype string

type Quickfix struct {
	Newline     string       `xml:"newline,omitempty" yaml:"newline,omitempty"`
	Replacement string       `xml:"replacement,omitempty" yaml:"replacement,omitempty"`
	Search      string       `xml:"search,omitempty" yaml:"search,omitempty"`
	Type        Quickfixtype `xml:"type,attr" yaml:"type"`
	Name        string       `xml:"name,attr" yaml:"name"`
}

// May be one of REPLACE, DELETE_LINE, INSERT_LINE
type Quickfixtype string

type Rule struct {
	When      When      `xml:"when" yaml:"when"`
	Perform   Iteration `xml:"perform" yaml:"perform"`
	Otherwise Iteration `xml:"otherwise,omitempty" yaml:"otherwise,omitempty"`
	Where     []Where   `xml:"where,omitempty" yaml:"where,omitempty"`
}

type Rules struct {
	Rule            []Rule            `xml:"rule,omitempty" yaml:"rule,omitempty"`
	Filemapping     []Mapping         `xml:"file-mapping,omitempty" yaml:"file-mapping,omitempty"`
	Packagemapping  []Mapping         `xml:"package-mapping,omitempty" yaml:"package-mapping,omitempty"`
	Javaclassignore []Javaclassignore `xml:"javaclass-ignore,omitempty" yaml:"javaclass-ignore,omitempty"`
}

type Ruleset struct {
	Metadata        []Metadata        `xml:"metadata,omitempty" yaml:"metadata,omitempty"`
	Rules           Rules             `xml:"rules" yaml:"rules"`
	Packagemapping  []Mapping         `xml:"package-mapping,omitempty" yaml:"package-mapping,omitempty"`
	Filemapping     []Mapping         `xml:"file-mapping,omitempty" yaml:"file-mapping,omitempty"`
	Javaclassignore []Javaclassignore `xml:"javaclass-ignore,omitempty" yaml:"javaclass-ignore,omitempty"`
	SourceFile      string            `yaml:"sourceFile"`
}

type Ruletest struct {
	TestDataPath string    `xml:"testDataPath" yaml:"testDataPath"`
	SourceMode   bool      `xml:"sourceMode,omitempty" yaml:"sourceMode,omitempty"`
	RulePath     []string  `xml:"rulePath,omitempty" yaml:"rulePath,omitempty"`
	Source       string    `xml:"source,omitempty" yaml:"source,omitempty"`
	Target       string    `xml:"target,omitempty" yaml:"target,omitempty"`
	Ruleset      []Ruleset `xml:"ruleset,omitempty" yaml:"ruleset,omitempty"`
}

type Tag struct {
	Name string `xml:"name,attr" yaml:"name"`
}

type Technology struct {
	Id           string `xml:"id,attr,omitempty" yaml:"id,omitempty"`
	VersionRange string `xml:"versionRange,attr,omitempty" yaml:"versionRange,omitempty"`
}

type Technologyidentified struct {
	Tag         []Tag  `xml:"tag,omitempty" yaml:"tag,omitempty"`
	Name        string `xml:"name,attr" yaml:"name"`
	Numberfound byte   `xml:"number-found,attr,omitempty" yaml:"number-found,omitempty"`
}

type Technologytag struct {
	Value string             `xml:",chardata" yaml:"value"`
	Level Technologytaglevel `xml:"level,attr,omitempty" yaml:"level,omitempty"`
}

type Technologytagexists struct {
	Technologytag string `xml:"technology-tag,attr" yaml:"technology-tag"`
	In            string `xml:"in,attr,omitempty" yaml:"in,omitempty"`
}

// May be one of INFORMATIONAL, IMPORTANT
type Technologytaglevel string

type When struct {
	True                       string                 `xml:"true,omitempty" yaml:"true,omitempty"`
	False                      string                 `xml:"false,omitempty" yaml:"false,omitempty"`
	Javaclass                  []Javaclass            `xml:"javaclass,omitempty" yaml:"javaclass,omitempty"`
	Xmlfile                    []Xmlfile              `xml:"xmlfile,omitempty" yaml:"xmlfile,omitempty"`
	Project                    []Project              `xml:"project,omitempty" yaml:"project,omitempty"`
	Filecontent                []Filecontent          `xml:"filecontent,omitempty" yaml:"filecontent,omitempty"`
	File                       []File                 `xml:"file,omitempty" yaml:"file,omitempty"`
	Classificationexists       []Classificationexists `xml:"classification-exists,omitempty" yaml:"classification-exists,omitempty"`
	Fileexists                 []Fileexists           `xml:"file-exists,omitempty" yaml:"file-exists,omitempty"`
	Hintexists                 []Hintexists           `xml:"hint-exists,omitempty" yaml:"hint-exists,omitempty"`
	Lineitemexists             []Lineitemexists       `xml:"lineitem-exists,omitempty" yaml:"lineitem-exists,omitempty"`
	Technologystatisticsexists []Technologyidentified `xml:"technology-statistics-exists,omitempty" yaml:"technology-statistics-exists,omitempty"`
	Iterablefilter             []Iterablefilter       `xml:"iterable-filter,omitempty" yaml:"iterable-filter,omitempty"`
	Tofilemodel                []Whenbase             `xml:"to-file-model,omitempty" yaml:"to-file-model,omitempty"`
	Graphquery                 []Graphquery           `xml:"graph-query,omitempty" yaml:"graph-query,omitempty"`
	Technologytagexists        []Technologytagexists  `xml:"technology-tag-exists,omitempty" yaml:"technology-tag-exists,omitempty"`
	Dependency                 []Dependency           `xml:"dependency,omitempty" yaml:"dependency,omitempty"`
	Or                         []When                 `xml:"or,omitempty" yaml:"or,omitempty"`
	And                        []When                 `xml:"and,omitempty" yaml:"and,omitempty"`
	Not                        []When                 `xml:"not,omitempty" yaml:"not,omitempty"`
}

type Whenbase struct {
	True                       string                 `xml:"true,omitempty" yaml:"true,omitempty"`
	False                      string                 `xml:"false,omitempty" yaml:"false,omitempty"`
	Javaclass                  []Javaclass            `xml:"javaclass,omitempty" yaml:"javaclass,omitempty"`
	Xmlfile                    []Xmlfile              `xml:"xmlfile,omitempty" yaml:"xmlfile,omitempty"`
	Project                    []Project              `xml:"project,omitempty" yaml:"project,omitempty"`
	Filecontent                []Filecontent          `xml:"filecontent,omitempty" yaml:"filecontent,omitempty"`
	File                       []File                 `xml:"file,omitempty" yaml:"file,omitempty"`
	Classificationexists       []Classificationexists `xml:"classification-exists,omitempty" yaml:"classification-exists,omitempty"`
	Fileexists                 []Fileexists           `xml:"file-exists,omitempty" yaml:"file-exists,omitempty"`
	Hintexists                 []Hintexists           `xml:"hint-exists,omitempty" yaml:"hint-exists,omitempty"`
	Lineitemexists             []Lineitemexists       `xml:"lineitem-exists,omitempty" yaml:"lineitem-exists,omitempty"`
	Technologystatisticsexists []Technologyidentified `xml:"technology-statistics-exists,omitempty" yaml:"technology-statistics-exists,omitempty"`
	Iterablefilter             []Iterablefilter       `xml:"iterable-filter,omitempty" yaml:"iterable-filter,omitempty"`
	Tofilemodel                []Whenbase             `xml:"to-file-model,omitempty" yaml:"to-file-model,omitempty"`
	Graphquery                 []Graphquery           `xml:"graph-query,omitempty" yaml:"graph-query,omitempty"`
	Technologytagexists        []Technologytagexists  `xml:"technology-tag-exists,omitempty" yaml:"technology-tag-exists,omitempty"`
	Dependency                 []Dependency           `xml:"dependency,omitempty" yaml:"dependency,omitempty"`
}

type Where struct {
	Matches []Matches `xml:"matches,omitempty" yaml:"matches,omitempty"`
	Param   string    `xml:"param,attr,omitempty" yaml:"param,omitempty"`
}

type Xmlfile struct {
	Namespace        []Namespace `xml:"namespace,omitempty" yaml:"namespace,omitempty"`
	As               string      `xml:"as,attr,omitempty" yaml:"as,omitempty"`
	XpathResultMatch string      `xml:"xpathResultMatch,attr,omitempty" yaml:"xpathResultMatch,omitempty"`
	Matches          string      `xml:"matches,attr,omitempty" yaml:"matches,omitempty"`
	Publicid         string      `xml:"public-id,attr,omitempty" yaml:"public-id,omitempty"`
	Systemid         string      `xml:"system-id,attr,omitempty" yaml:"system-id,omitempty"`
	In               string      `xml:"in,attr,omitempty" yaml:"in,omitempty"`
	From             string      `xml:"from,attr,omitempty" yaml:"from,omitempty"`
}

type Xslt struct {
	Xsltparameter []Xsltparameter `xml:"xslt-parameter,omitempty" yaml:"xslt-parameter,omitempty"`
	Of            string          `xml:"of,attr,omitempty" yaml:"of,omitempty"`
	Title         string          `xml:"title,attr" yaml:"title"`
	Extension     string          `xml:"extension,attr" yaml:"extension"`
	Template      string          `xml:"template,attr" yaml:"template"`
	Usesaxon      bool            `xml:"use-saxon,attr,omitempty" yaml:"use-saxon,omitempty"`
	Effort        byte            `xml:"effort,attr,omitempty" yaml:"effort,omitempty"`
}

type Xsltparameter struct {
	Value     string `xml:",chardata" yaml:"value"`
	Property  string `xml:"property,attr,omitempty" yaml:"property,omitempty"`
	ValueAttr string `xml:"value,attr,omitempty" yaml:"value,omitempty"`
}
