package config

import (
	"regexp"
)

// Constants for configuration and limits
const (
	// Regex file name and limits
	REGEXFILE = "regexes.json"

	// Configuration directory and file details
	configDir  = ".config/varunastra"
	configFile = "config.yaml"
	configURL  = "https://devanghacks.in/varunastra/config.yaml"
)

// Global variables
var (
	regexes RegexConfig // Configuration for regex patterns
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

// CLI struct defines command-line options and subcommands
type CLI struct {
	Target string `kong:"required,help='Target string'"`                      // Target to scan
	Scans  string `kong:"help='Comma-separated scans (secrets,vuln,assets)'"` // Scans to perform
}

// RegexConfig defines a map for regex patterns
type RegexConfig map[string]string

// RegexDB holds a compiled regex pattern
type RegexDB struct {
	ID      string         // Identifier for the regex
	Pattern *regexp.Regexp // Compiled regex pattern
}

// ExcludedPatterns is a custom type for a slice of regex patterns
type ExcludedPatterns []*regexp.Regexp
type ScanMap map[string]bool
