package deps

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

// HandleDependencyFile processes and checks a specific dependency file
func HandleDependencyFile(fileName string, tr *tar.Reader) ([]VulnIssue, error) {
	var issues []VulnIssue
	var err error

	tracker := NewFileTracker()

	// Check if the file has already been seen
	if tracker.IsFileSeen(fileName) {
		return nil, fmt.Errorf("we have seen %s already", fileName)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", fileName, err)
	}
	content := buf.Bytes()

	tracker.MarkFileAsSeen(fileName) // Mark the file as seen

	switch {
	case strings.HasSuffix(fileName, "package-lock.json"):
		if issues, err = handlePackageLockJSON(fileName, &content); err != nil {
			return nil, err
		}
	case strings.HasSuffix(fileName, "Gemfile.lock"):
		if issues, err = handleGemLockfile(fileName, &content); err != nil {
			return nil, err
		}
	case strings.HasSuffix(fileName, "yarn.lock"):
		if issues, err = handleYarnLockDependencies(fileName, &content); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported dependency file type: %s", fileName)
	}

	tracker.ClearSeenMap()
	return issues, nil
}

// handlePackageLockJSON processes a package-lock.json file to check for vulnerabilities and dependency confusion
func handlePackageLockJSON(fileName string, content *[]byte) ([]VulnIssue, error) {
	var issues []VulnIssue
	if strings.Contains(fileName, "node_modules") {
		return nil, fmt.Errorf("skipping package-lock.json file in node_modules: %s", fileName)
	}

	log.Printf("Processing: %s", fileName)

	var data map[string]interface{}
	if err := json.Unmarshal(*content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", fileName, err)
	}

	dependencies := extractPackageLockDependencies(data)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	var allErrors []error // Collect all errors

	for _, dep := range dependencies {
		vissue, err := checkDependencyVulnerabilities(dep, fileName, "npm")
		if err != nil {
			// Log the error and continue with the next dependency
			allErrors = append(allErrors, err)
			continue // Skip to the next dependency
		}

		cissue, err := checkNPMDependencyConfusion(dep)
		if err != nil {
			// Log the error and continue with the next dependency
			allErrors = append(allErrors, err)
			continue // Skip to the next dependency
		}

		issues = append(issues, vissue...)
		issues = append(issues, cissue...)
	}

	// After the loop, you can handle the collected errors if needed
	if len(allErrors) > 0 {
		// You could return a summary of errors or handle them as needed
		return nil, fmt.Errorf("encountered errors while processing dependencies: %v", allErrors)
	}

	return issues, nil
}

func handleYarnLockDependencies(fileName string, content *[]byte) ([]VulnIssue, error) {
	var issues []VulnIssue
	if strings.Contains(fileName, "node_modules") {
		return nil, fmt.Errorf("skipping yarn.lock file in node_modules: %s", fileName)
	}

	log.Printf("Processing: %s", fileName)

	dependencies := extractYarnLockDependencies(content)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	for _, dep := range dependencies {
		vissue, err := checkDependencyVulnerabilities(dep, fileName, "npm")
		if err != nil {
			return nil, err
		}
		cissue, err := checkNPMDependencyConfusion(dep)
		if err != nil {
			return nil, err
		}

		issues = append(issues, vissue...)
		issues = append(issues, cissue...)
	}

	return issues, nil
}

// handleGemLockfile processes a Gemfile.lock to check for vulnerabilities and dependency confusion.
func handleGemLockfile(fileName string, content *[]byte) ([]VulnIssue, error) {
	var issues []VulnIssue
	log.Printf("Handling Gemfile.lock: %s", fileName)

	dependencies := rubyaudit.ExtractGemfileLockDependenciesRaw(content)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion.
	for _, dep := range dependencies {
		vissue, err := checkGemDependencyVulnerabilities(dep, fileName)
		if err != nil {
			return nil, err
		}

		cissue, err := checkGemDependencyConfusion(dep)
		if err != nil {
			return nil, err
		}

		issues = append(issues, vissue...)
		issues = append(issues, cissue...)
	}

	return issues, nil
}
