package deps

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

type FileTracker struct {
	seen map[string]bool
}

// NewFileTracker creates and returns a new FileTracker instance
func NewFileTracker() *FileTracker {
	return &FileTracker{
		seen: make(map[string]bool),
	}
}

// MarkFileAsSeen marks the specified file as processed
func (ft *FileTracker) MarkFileAsSeen(fileName string) {
	ft.seen[fileName] = true
}

// IsFileSeen checks if the specified file has been marked as seen
func (ft *FileTracker) IsFileSeen(fileName string) bool {
	return ft.seen[fileName]
}

// ClearSeenMap clears the seen map
func (ft *FileTracker) ClearSeenMap() {
	ft.seen = make(map[string]bool) // Reinitialize the map
}

// isKnownDependencyFile checks if a file is one of the known dependency files
func IsKnownDependencyFile(fileName string) bool {
	for _, knownFile := range KnownDependencyFiles {
		if strings.HasSuffix(fileName, knownFile) {
			return true
		}
	}
	return false
}

// cleanVersion cleans the version string to remove any non-numeric, non-dot characters
func cleanVersion(deb Dependency) Dependency {

	if strings.Contains(deb.Version, "npm:") {
		// Extract the version after the '@' symbol
		versionParts := strings.Split(deb.Version, "@")
		if len(versionParts) == 2 {
			deb.Version = versionParts[1] // Get the version part
			// Clean the name by removing the 'npm:' prefix
			deb.Name = strings.TrimPrefix(versionParts[0], "npm:")
		}
	}

	// Define a regex to match valid version components (digits and dots)
	re := regexp.MustCompile(`^[~^<>=\s]*(\d+\.\d+\.\d+.*)`)
	matches := re.FindStringSubmatch(deb.Version)

	if len(matches) > 1 {
		// Return the first capture group, which is the cleaned version
		deb.Version = matches[1]
		return deb
	}
	// If no matches are found, return the original version as a fallback
	return deb
}

// getAdvisoryDetails fetches detailed information about a security advisory
func getAdvisoryDetails(advisoryID string) (AdvisoryDetails, error) {
	// Construct the API URL for fetching the advisory details
	apiURL := fmt.Sprintf("https://api.deps.dev/v3/advisories/%s", advisoryID)

	// Perform the HTTP GET request
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Printf("Failed to fetch advisory details for %s: %v", advisoryID, err)
		return AdvisoryDetails{}, err
	}
	defer resp.Body.Close()

	// Check if the response status is not 200 (OK)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch advisory details for %s: HTTP status %d", advisoryID, resp.StatusCode)
		return AdvisoryDetails{}, err
	}

	// Parse the response JSON
	var details AdvisoryDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		log.Printf("Failed to parse advisory details for %s: %v", advisoryID, err)
		return AdvisoryDetails{}, err
	}

	// Log the detailed advisory information
	fmt.Println()
	log.Printf("Advisory Details for ID %s:", advisoryID)
	log.Printf("- URL: %s", details.URL)
	log.Printf("- Title: %s", details.Title)
	log.Printf("- Aliases: %v", details.Aliases)
	log.Printf("- CVSS v3 Score: %.1f", details.CVSS3Score)
	log.Printf("- CVSS v3 Vector: %s", details.CVSS3Vector)
	fmt.Println()
	return details, nil
}

// addIssueDetails adds details about a vulnerability or dependency issue to the final result set.
func addDepenDencyIssueDetails[T AdvisoryDetails | string | []rubyaudit.Advisory, D Dependency | rubyaudit.Dependency](details T, filename string, dep D, env string) VulnIssue {
	var issue VulnIssue
	switch v := any(details).(type) {
	case AdvisoryDetails:
		issue.Issue = v.AdvisoryKey.ID
		issue.Title = v.Title
		issue.Ref = v.URL
		issue.CVSS3Score = v.CVSS3Score
	case string:
		issue.Issue = "Dependency Confusion"
		switch d := any(details).(type) {
		case Dependency:
			issue.Title = fmt.Sprintf("The package %s was not found in the public repository of %s", d.Name, env)
			issue.CVSS3Score = 5
		}
	case []rubyaudit.Advisory:
		for _, vv := range v {
			issue.Issue = vv.CVE
			issue.Title = vv.Title
			issue.Ref = vv.URL
		}
	}
	switch v := any(dep).(type) {
	case Dependency:
		issue.Path = fmt.Sprintf("Package: %s, File: %s", v.Name+":"+v.Version, filename)
	case rubyaudit.Dependency:
		issue.Path = fmt.Sprintf("Package: %s, File: %s", v.Name+":"+v.Version, filename)
	}

	return issue
}
