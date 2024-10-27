package docker

import "github.com/Devang-Solanki/RedHunt/Varunastra/deps"

// Constants for configuration and limits
const (
	maxFileSize   = 100 * 1024 * 1024 // 100MB in bytes
	workerCount   = 5
	maxGoroutines = 10

	// Special path indicators
	opq = ".wh..wh..opq"
	wh  = ".wh."
)

// Global variables
var (
	taskChannel = make(chan SecretScanTask, 50) // Channel for secret scan tasks
	finalOutput FinalOutput                     // Output structure for scan results
	scanMap     = make(map[string]bool)         // Map to track enabled scans
)

// FetchTagNameResponse represents the response from fetching a tag name
type FetchTagNameResponse struct {
	ImageName string `json:"tag"` // Image name tag
}

// FinalOutput represents the final results of the scan
type FinalOutput struct {
	Target        string           `json:"target"`          // Target scanned
	Secrets       []SecretIssue    `json:"secrets"`         // Found secrets
	Vulnerability []deps.VulnIssue `json:"vulnerabilities"` // Found vulnerabilities
}

// SecretIssue represents an identified secret issue
type SecretIssue struct {
	Issue  string `json:"issue"`  // Description of the issue
	Path   string `json:"asset"`  // Path where the issue was found
	Type   string `json:"type"`   // Type of the secret
	Secret string `json:"secret"` // The secret itself
}

// DBData represents data structure for database information
type DBData struct {
	Issue      string `json:"issue"`    // Issue description
	Severity   string `json:"severity"` // Severity of the issue
	Validators struct {
		Status []int    `json:"status"` // Status codes for validation
		Regex  []string `json:"regex"`  // List of regex patterns for validation
	} `json:"validators"`
	Extractors []struct {
		Regex   string `json:"regex"`   // Regex for extraction
		Cgroups string `json:"cgroups"` // Cgroups associated with the extractor
	} `json:"extractors"`
}

// SecretScanTask represents a task for scanning secrets
type SecretScanTask struct {
	Path      string
	Content   *[]byte
	ID        interface{}
	ImageName string
}
