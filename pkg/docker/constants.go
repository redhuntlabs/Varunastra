package docker

import "github.com/redhuntlabs/Varunastra/pkg/deps"

// Constants for configuration and limits
const (
	maxFileSize   = 200 * 1024 * 1024 // 100MB in bytes
	workerCount   = 1000
	maxGoroutines = 10

	// Special path indicators
	opq = ".wh..wh..opq"
	wh  = ".wh."
)

// FetchTagNameResponse represents the response from fetching a tag name
type FetchTagNameResponse struct {
	ImageName string `json:"tag"` // Image name tag
}

type SubAndDom struct {
	Subdomains []string `json:"subdomains"`
	Domain     string   `json:"domain"`
}

// FinalOutput represents the final results of the scan
type FinalOutput struct {
	Target        string           `json:"target"`          // Target scanned
	Secrets       []SecretIssue    `json:"secrets"`         // Found secrets
	Vulnerability []deps.VulnIssue `json:"vulnerabilities"` // Found vulnerabilities
	Assets        Assets           `json:"assets"`
}

type Assets struct {
	Domains []SubAndDom `json:"assets"`
	Urls    []string    `json:"urls"`
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

// List of custom resolvers (DNS servers)
var resolvers = []string{
	"1.0.0.1",
	"1.1.1.1",
	"149.112.112.112",
	"185.228.168.9",
	"185.228.169.9",
	"195.46.39.39",
	"195.46.39.40",
	"205.171.2.65",
	"205.171.3.65",
	"208.67.220.220",
	"208.67.222.222",
	"216.146.35.35",
	"216.146.36.36",
	"64.6.64.6",
	"64.6.65.6",
	"74.82.42.42",
	"76.76.10.0",
	"76.76.2.0",
	"77.88.8.1",
	"77.88.8.8",
	"8.20.247.20",
	"8.26.56.26",
	"8.8.4.4",
	"8.8.8.8",
	"84.200.70.40",
	"9.9.9.9",
	"94.140.14.14",
	"94.140.15.15",
}
