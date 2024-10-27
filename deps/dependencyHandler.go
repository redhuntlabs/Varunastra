package deps

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"example.com/varunastra/docker"
	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

var (
	issues []VulnIssue
)

// handleDependencyFile processes and checks a specific dependency file
func HandleDependencyFile(fileName string, tr *tar.Reader, output *docker.FinalOutput) error {

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		return fmt.Errorf("failed to read file %s: %v", fileName, err)

	}
	content := buf.Bytes()

	switch {
	case strings.HasSuffix(fileName, "package-lock.json"): // || strings.HasSuffix(fileName, "package.json"):
		handlePackageLockJSON(fileName, &content)
	case strings.HasSuffix(fileName, "Gemfile.lock"):
		handleGemLockfile(fileName, &content)
	case strings.HasSuffix(fileName, "yarn.lock"):
		handleYarnLockDependencies(fileName, &content)

	// Add other cases for different file types
	default:
		return fmt.Errorf("unsupported dependency file type: %s", fileName)
	}

	output.Vulnerability = append(output.Vulnerability, issues)
	return nil
}

// handlePackageLockJSON processes a package-lock.json file to check for vulnerabilities and dependency confusion
func handlePackageLockJSON(fileName string, content *[]byte) {
	if strings.Contains(fileName, "node_modules") {
		log.Printf("Skipping non package-lock.json file: %s", fileName)
		return
	}

	log.Printf("Processing: %s", fileName)

	var data map[string]interface{}
	if err := json.Unmarshal(*content, &data); err != nil {
		log.Printf("Failed to parse %s: %v", fileName, err)
		return
	}

	dependencies := extractPackageLockDependencies(data)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	for _, dep := range dependencies {
		checkDependencyVulnerabilities(dep, fileName, "npm")
		checkNPMDependencyConfusion(dep)
	}
}

func handleYarnLockDependencies(fileName string, content *[]byte) {
	// if strings.Contains(fileName, "node_modules") {
	// 	log.Printf("Skipping non yarn.lock file: %s", fileName)
	// 	return
	// }

	log.Printf("Processing: %s", fileName)

	dependencies := extractYarnLockDependencies(content)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	for _, dep := range dependencies {
		checkDependencyVulnerabilities(dep, fileName, "npm")
		checkNPMDependencyConfusion(dep)
	}
}

// handleGemLockfile processes a Gemfile.lock to check for vulnerabilities and dependency confusion.
func handleGemLockfile(fileName string, content *[]byte) {
	log.Printf("Handling Gemfile.lock: %s", fileName)

	dependencies := rubyaudit.ExtractGemfileLockDependenciesRaw(content)

	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion.
	for _, dep := range dependencies {
		checkGemDependencyVulnerabilities(dep, fileName)
		// checkGemDependencyConfusion(dep)
	}
}

// isKnownDependencyFile checks if a file is one of the known dependency files
func isKnownDependencyFile(fileName string) bool {
	for _, knownFile := range KnownDependencyFiles {
		if strings.HasSuffix(fileName, knownFile) {
			return true
		}
	}
	return false
}
