package deps

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

// cleanVersion cleans the version string to remove any non-numeric, non-dot characters
func cleanVersion(version string) string {
	// Define a regex to match valid version components (digits and dots)
	re := regexp.MustCompile(`^[~^<>=\s]*(\d+\.\d+\.\d+.*)`)
	matches := re.FindStringSubmatch(version)

	if len(matches) > 1 {
		// Return the first capture group, which is the cleaned version
		return matches[1]
	}
	// If no matches are found, return the original version as a fallback
	return version
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
	log.Printf("Advisory Details for ID %s:", advisoryID)
	log.Printf("- URL: %s", details.URL)
	log.Printf("- Title: %s", details.Title)
	log.Printf("- Aliases: %v", details.Aliases)
	log.Printf("- CVSS v3 Score: %.1f", details.CVSS3Score)
	log.Printf("- CVSS v3 Vector: %s", details.CVSS3Vector)

	return details, nil
}

// addIssueDetails adds details about a vulnerability or dependency issue to the final result set.
func addDepenDencyIssueDetails[T AdvisoryDetails | string | []rubyaudit.Advisory, D Dependency | rubyaudit.Dependency](details T, filename string, dep D, env string) {
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
	switch v := any(details).(type) {
	case Dependency:
		issue.Path = fmt.Sprintf("Package: %s, File: %s", v.Name+":"+v.Version, filename)
	case rubyaudit.Dependency:
		issue.Path = fmt.Sprintf("Package: %s, File: %s", v.Name+":"+v.Version, filename)
	}

	issues = append(issues, issue)
}
