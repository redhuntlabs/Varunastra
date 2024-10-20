package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func handleSpecialFiles(fileName string) bool {

	if fileName == opq || strings.Contains(fileName, wh) {
		return true
	}
	return false
}

// handleGitRepo handles the git repository detection
func handleGitRepo(fileName string) {
	var finalResult []VulnIssue

	issue := VulnIssue{
		Issue:      "Git Repo in the Image",
		Path:       fileName,
		CVSS3Score: 0,
		Ref:        "https://www.firecompass.com/blog/how-do-attackers-utilize-git-for-fun-and-profit/",
	}

	finalOutput.Vulnerability = append(finalResult, issue)
}

// isExcluded checks if a file path matches any of the excluded patterns
func isExcluded(filePath string) bool {
	// Normalize file path separators for cross-platform compatibility
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")

	// Check if the normalized file path matches any exclusion pattern
	for _, pattern := range excludedPatterns {
		if pattern.MatchString(normalizedPath) {
			return true
		}
	}
	return false
}

func processLargeFile(tr *tar.Reader, fileName string, digest v1.Hash, imageName string) error {
	tempFile, err := os.CreateTemp("", "large-file-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name()) // Ensure the temp file is deleted

	// Write the tar content to the temp file
	if _, err := io.Copy(tempFile, tr); err != nil {
		return fmt.Errorf("failed to copy tar content to temp file: %w", err)
	}

	// Reopen the temp file for reading
	tempFile.Seek(0, io.SeekStart)
	if err := processFileFromTemp(tempFile, fileName, digest, imageName); err != nil {
		return fmt.Errorf("error scanning file from temp file: %w", err)
	}

	return nil
}

func processSmallFile(tr *tar.Reader, fileName string, digest v1.Hash, imageName string) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		return fmt.Errorf("failed to read file %s: %v", fileName, err)

	}
	content := buf.Bytes()

	queueTask(fileName, &content, digest, imageName)

	return nil
}

func processFileFromTemp(tempFile *os.File, fileName string, digest v1.Hash, imageName string) error {
	const bufferSize = 4096
	buffer := make([]byte, bufferSize)

	for {
		n, err := tempFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read temp file content: %w", err)
		}
		if n == 0 {
			break
		}
		if err == io.EOF {
			break
		}
		content := buffer[:n]
		queueTask(fileName, &content, digest, imageName)
	}
	return nil
}
