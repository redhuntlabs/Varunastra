package main

import (
	"regexp"
)

// Constants for configuration and limits
const (
	// Regex file name and limits
	REGEXFILE     = "regexes.json"
	maxFileSize   = 100 * 1024 * 1024 // 100MB in bytes
	workerCount   = 5
	maxGoroutines = 10

	// Special path indicators
	opq = ".wh..wh..opq"
	wh  = ".wh."

	// Configuration directory and file details
	configDir  = ".config/varunastra"
	configFile = "config.yaml"
	configURL  = "https://devanghacks.in/varunastra/config.yaml"
)

// Global variables
var (
	taskChannel = make(chan SecretScanTask, 50) // Channel for secret scan tasks
	regexes     RegexConfig                     // Configuration for regex patterns
	regexStore  []RegexDB                       // Store for compiled regex patterns
	finalOutput FinalOutput                     // Output structure for scan results
	scanMap     = make(map[string]bool)         // Map to track enabled scans
)

// Config represents the structure of the configuration file
type Config struct {
	RegexFiles          RegexFilesConfig     `yaml:"regex_files"`          // Nested structure for regex files          // Path to regex files
	BlacklistedPatterns []BlacklistedPattern `yaml:"blacklisted_patterns"` // List of blacklisted paths
}

// New struct to represent the regex files configuration
type RegexFilesConfig struct {
	Path string `yaml:"path"` // Path to the regex file
}

// Struct to represent each blacklisted pattern
type BlacklistedPattern struct {
	Pattern string `yaml:"pattern"` // Pattern for the blacklisted path
}

// FetchTagNameResponse represents the response from fetching a tag name
type FetchTagNameResponse struct {
	ImageName string `json:"tag"` // Image name tag
}

// CLI struct defines command-line options and subcommands
type CLI struct {
	Target string `kong:"required,help='Target string'"`                      // Target to scan
	Scans  string `kong:"help='Comma-separated scans (secrets,vuln,assets)'"` // Scans to perform
}

// RegexConfig defines a map for regex patterns
type RegexConfig map[string]string

// FinalOutput represents the final results of the scan
type FinalOutput struct {
	Target        string        `json:"target"`          // Target scanned
	Secrets       []SecretIssue `json:"secrets"`         // Found secrets
	Vulnerability []VulnIssue   `json:"vulnerabilities"` // Found vulnerabilities
}

// SecretIssue represents an identified secret issue
type SecretIssue struct {
	Issue  string `json:"issue"`  // Description of the issue
	Path   string `json:"asset"`  // Path where the issue was found
	Type   string `json:"type"`   // Type of the secret
	Secret string `json:"secret"` // The secret itself
}

// VulnIssue represents an identified vulnerability issue
type VulnIssue struct {
	Issue      string  `json:"issue"`     // Description of the vulnerability
	Path       string  `json:"asset"`     // Path where the vulnerability was found
	Title      string  `json:"title"`     // Title of the vulnerability
	CVSS3Score float64 `json:"cvss3"`     // CVSS score
	Ref        string  `json:"Reference"` // Reference link for the vulnerability
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

// RegexDB holds a compiled regex pattern
type RegexDB struct {
	ID      string         // Identifier for the regex
	Pattern *regexp.Regexp // Compiled regex pattern
}

// Global slice to hold excluded patterns
var excludedPatterns []*regexp.Regexp
