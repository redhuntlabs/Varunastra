package config

import (
	regexp "github.com/wasilibs/go-re2"

	"github.com/redhuntlabs/Varunastra/pkg/deps"
)

// Constants for configuration and limits
const (
	// Regex file name and limits
	REGEXFILE = "regexes.json"

	// Configuration directory and file details
	configDir  = ".config/varunastra"
	configFile = "config.yaml"
	configURL  = "https://raw.githubusercontent.com/redhuntlabs/Varunastra/refs/heads/main/data/config.yaml"
)

// Global variables
var (
	regexes RegexConfig // Configuration for regex patterns
)

// Config represents the structure of the configuration file
type Config struct {
	RegexFiles          RegexFilesConfig     `yaml:"regex_files"`          // Nested structure for regex files          // Path to regex files
	BlacklistedPatterns []BlacklistedPattern `yaml:"blacklisted_patterns"` // List of blacklisted paths
	WhitelistedPatterns []WhitelistedPattern `yaml:"whitelisted_patterns"` // List of whitelisted paths
}

// New struct to represent the regex files configuration
type RegexFilesConfig struct {
	Path string `yaml:"path"` // Path to the regex file
}

// Struct to represent each blacklisted pattern
type BlacklistedPattern struct {
	Pattern string `yaml:"pattern"` // Pattern for the blacklisted path
}

// Struct to represent each blacklisted pattern
type WhitelistedPattern struct {
	Pattern string `yaml:"pattern"` // Pattern for the blacklisted path
}

// CLI struct defines command-line options and subcommands
type CLI struct {
	Target string `kong:"required,help='Target repos'"`                                                                      // Target to scan
	Scans  string `kong:"help='Comma-separated scans (secrets,vuln,assets). By default all are true if not specified any.'"` // Scans to perform
	All    bool   `kong:"help='Enable scanning for all tags.'"`
	Output string `kong:"help='Save JSON output to a file'"`
	Html   string `kong:"help='Save HTML report to a file'"`
}

// RegexConfig defines a map for regex patterns
type RegexConfig map[string]string

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

// ExcludedPatterns is a custom type for a slice of regex patterns
type ExcludedPatterns []*regexp.Regexp
type WhitelistedPatterns []*regexp.Regexp
type ScanMap map[string]bool

// RegexDB holds a compiled regex pattern
type RegexDB struct {
	ID      string         // Identifier for the regex
	Pattern *regexp.Regexp // Compiled regex pattern
}
