package execution

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	pathlib "path"
	"path/filepath"
	"strings"

	"github.com/konveyor/analyzer-lsp/output/v1/konveyor"
	"github.com/konveyor/analyzer-lsp/provider"
)

type Command struct {
	BinPath        string
	Env            []string
	Dir            string
	OutputPath     string
	SourceCodePath string
	WorkDirPath    string
	Targets        []string
}

type WindupCmd struct {
	Command
	SourceMode bool
	WithDeps   bool
}

type AnalyzerCmd struct {
	Command
	ProviderSettingsPath string
	RulesPath            string
	LabelSelector        string
}

func (c *Command) Run(args ...string) error {
	logFile, err := os.Create(
		filepath.Join(c.WorkDirPath, fmt.Sprintf("%s.log", filepath.Base(c.BinPath))))
	if err != nil {
		log.Printf("failed to create log file")
		return err
	}
	log.Printf("executing -- %s %s\n", c.BinPath, strings.Join(args, " "))
	log.Printf("writing logs to %s\n", logFile.Name())
	cmd := exec.Command(c.BinPath, args...)
	cmd.Stderr = logFile
	cmd.Stdout = logFile
	if c.Dir != "" {
		cmd.Dir = c.Dir
	}
	err = cmd.Run()
	if err != nil {
		log.Printf(
			"failed running command -- %s %s -- %v\n",
			c.BinPath, strings.Join(args, " "), err)
		return err
	}
	return nil
}

func (c *WindupCmd) Run() error {
	args, err := c.args()
	if err != nil {
		log.Println("failed to get options")
		return err
	}
	err = c.Command.Run(args...)
	if err != nil {
		return err
	}
	return nil
}

func (c *WindupCmd) args() ([]string, error) {
	args := []string{
		"--input", c.SourceCodePath,
		"--output", c.OutputPath,
		"--analyzeKnownLibraries",
	}
	for _, target := range c.Targets {
		args = append(args, []string{"--target", target}...)
	}
	if c.SourceMode {
		args = append(args, "--sourceMode")
	}
	if c.WithDeps {
		depPath := pathlib.Join(c.WorkDirPath, "deps")
		m2Path := pathlib.Join(c.SourceCodePath, "m2")
		depCmd := Command{
			BinPath:     "/usr/bin/mvn",
			Dir:         c.SourceCodePath,
			WorkDirPath: c.WorkDirPath,
		}
		mvnArgs := []string{
			"dependency:copy-dependencies",
			"-f",
			"pom.xml",
			fmt.Sprintf("-DoutputDirectory=%s", depPath),
			fmt.Sprintf("-Dmaven.repo.local=%s", m2Path),
			"-Dmaven.wagon.http.ssl.insecure=true",
		}
		log.Println("pulling dependencies for the app")
		err := depCmd.Run(mvnArgs...)
		if err != nil {
			log.Printf("failed to get dependencies for application")
			return nil, err
		}
		args = append(args, "--input", depPath)
	}
	return args, nil
}

func (c *AnalyzerCmd) Run() error {
	args, err := c.args()
	if err != nil {
		log.Println("failed to get args for analyzer cmd")
		return err
	}
	err = c.Command.Run(args...)
	if err != nil {
		return err
	}
	return nil
}

func (c *AnalyzerCmd) args() ([]string, error) {
	args := []string{
		"--rules", c.RulesPath,
		"--output-file", c.OutputPath,
	}
	targets := []string{}
	for _, target := range c.Targets {
		targets = append(targets,
			fmt.Sprintf("%s=%s", konveyor.TargetTechnologyLabel, target))
	}
	if len(targets) > 0 {
		c.LabelSelector = fmt.Sprintf("(%s) || (%s)",
			strings.Join(targets, "||"), c.LabelSelector)

	}
	args = append(args, "--label-selector", c.LabelSelector)
	path, err := c.writeProviderSettings()
	if err != nil {
		return nil, err
	}
	args = append(args, "--provider-settings", path)
	return args, nil
}

func (c AnalyzerCmd) writeProviderSettings() (string, error) {
	providerConfig := []provider.Config{
		{
			Name: "java",
			InitConfig: []provider.InitConfig{
				{
					Location: c.SourceCodePath,
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
					Location: c.SourceCodePath,
				},
			},
		},
	}
	path := filepath.Join(c.WorkDirPath, "provider_settings.json")
	err := writeJSON(providerConfig, path)
	if err != nil {
		return path, err
	}
	return path, nil
}
