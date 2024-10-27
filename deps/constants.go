package deps

// Parse the response JSON
var response struct {
	AdvisoryKeys []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
	} `json:"advisoryKeys"`
}

// KnownDependencyFiles lists the files we are interested in for dependency checking
var KnownDependencyFiles = []string{
	"package.json",
	"package-lock.json",
	"yarn.lock",
	"Gemfile",
	"Gemfile.lock",
	"requirements.txt",
	"Pipfile",
	"Pipfile.lock",
	"go.mod",
	"go.sum",
}

// Dependency represents a single dependency in package.json
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// AdvisoryDetails represents detailed information about a security advisory
type AdvisoryDetails struct {
	AdvisoryKey struct {
		ID string `json:"id"`
	} `json:"advisoryKey"`
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Aliases     []string `json:"aliases"`
	CVSS3Score  float64  `json:"cvss3Score"`
	CVSS3Vector string   `json:"cvss3Vector"`
}

// VulnIssue represents an identified vulnerability issue
type VulnIssue struct {
	Issue      string  `json:"issue"`     // Description of the vulnerability
	Path       string  `json:"asset"`     // Path where the vulnerability was found
	Title      string  `json:"title"`     // Title of the vulnerability
	CVSS3Score float64 `json:"cvss3"`     // CVSS score
	Ref        string  `json:"Reference"` // Reference link for the vulnerability
}
