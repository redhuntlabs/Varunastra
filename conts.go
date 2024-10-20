package main

import (
	"regexp"
)

const (
	REGEXFILE            = "regexes.json"
	maxFileSize          = 100 * 1024 * 1024 // 100MB in bytes
	workerCount          = 5
	maxGoroutines        = 10
	opq           string = ".wh..wh..opq"
	wh            string = ".wh."
)

var (
	taskChannel = make(chan SecretScanTask, 50) // Buffer size can be adjusted
	regexes     RegexConfig
	regexStore  []RegexDB
	finalOutput FinalOutput
)

type FetchTagNameResponse struct {
	ImageName string `json:"tag"`
}

type SendResultRequest struct {
	SlaveID string `json:"slave_id"`
	TagName string `json:"tag_name"`
	Status  string `json:"status"`
}

type RegexConfig map[string]string

type (
	FinalOutput struct {
		Target        string        `json:"target"`
		Secrets       []SecretIssue `json:"secrets"`
		Vulnerability []VulnIssue   `json:"vulnerabilities"`
	}
	SecretIssue struct {
		Issue  string `json:"issue"`
		Path   string `json:"asset"`
		Type   string `json:"type"`
		Secret string `json:"secret"`
	}
	VulnIssue struct {
		Issue      string  `json:"issue"`
		Path       string  `json:"asset"`
		Title      string  `json:"title"`
		CVSS3Score float64 `json:"cvss3"`
		Ref        string  `json:"Reference"`
	}
	DBData struct {
		Issue      string `json:"issue"`
		Severity   string `json:"severity"`
		Validators struct {
			Status []int    `json:"status"`
			Regex  []string `json:"regex"`
		} `json:"validators"`
		Extractors []struct {
			Regex   string `json:"regex"`
			Cgroups string `json:"cgroups"`
		} `json:"extractors"`
	}
)

type SecretScanTask struct {
	Path      string
	Content   *[]byte
	ID        interface{}
	ImageName string
}

type RegexDB struct {
	ID      string
	Pattern *regexp.Regexp
}

var excludedPatterns = []struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
}{
	{
		ID:          "opt-yarn",
		Description: "Yarn package paths",
		Pattern:     regexp.MustCompile(`(?i)opt\/yarn-v[\d.]+\/`),
	},
	{
		ID:          "opt-random",
		Description: "Oracle Packages paths",
		Pattern:     regexp.MustCompile(`(?i)opt\/(oracle|google|python\/lib|datadog-agent)\/`),
	},
	{
		ID:          "Google-Shit",
		Description: "Google Puppeteer",
		Pattern:     regexp.MustCompile(`(?i)(?i)\.cache\/puppeteer\/`),
	},
	{
		ID:          "golang",
		Description: "Go binary and library paths",
		Pattern:     regexp.MustCompile(`(?i)usr\/local\/go\/`),
	},
	{
		ID:          "python-lib",
		Description: "Python library paths",
		Pattern:     regexp.MustCompile(`(?i)(usr\/local\/(lib|include)\/python[\d.]+\/)|(\/\.cache\/pip)|(\/python[\d.]+\/(site|dist)\-packages\/)`),
	},
	{
		ID:          "rubygems",
		Description: "Ruby gems paths",
		Pattern:     regexp.MustCompile(`(?i)usr\/lib\/gems\/`),
	},
	{
		ID:          "wordpress-src",
		Description: "WordPress source paths",
		Pattern:     regexp.MustCompile(`(?i)usr\/src\/wordpress\/`),
	},
	{
		ID:          "anaconda-log",
		Description: "Anaconda CI log paths",
		Pattern:     regexp.MustCompile(`(?i)var\/log\/anaconda\/`),
	},
	{
		ID:          "usr-share",
		Description: "Directories under /usr/share and /tmp",
		Pattern:     regexp.MustCompile(`(?i)usr\/(local|share)`),
	},
	{
		ID:          "usr-dirs",
		Description: "System dirs",
		Pattern:     regexp.MustCompile(`^usr\/(?:share|include|lib)\/`),
	},
	{
		ID:          "var-tmp-cache",
		Description: "Directories under /var/tmp and /var/cache",
		Pattern:     regexp.MustCompile(`(?i)var/(?:tmp|cache|run)`),
	},
	{
		ID:          "usr-include-src",
		Description: "Directories under /usr/include and /usr/src",
		Pattern:     regexp.MustCompile(`(?i)usr/include|usr/src`),
	},
	{
		ID:          "var-lib-node_modules",
		Description: "Directories under /var/lib and node_modules",
		Pattern:     regexp.MustCompile(`(?i)var/lib|node_modules`),
	},
	{
		ID:          "dist-packages-vendor",
		Description: "dist-packages and vendor directories",
		Pattern:     regexp.MustCompile(`(?i)dist-packages|vendor`),
	},
	{
		ID:          "pycache-pip-cache",
		Description: "__pycache__ and pip-cache directories",
		Pattern:     regexp.MustCompile(`(?i)__pycache__|pip-cache`),
	},
	{
		ID:          "cargo-tests",
		Description: ".cargo and test directories",
		Pattern:     regexp.MustCompile(`(?i)\.cargo|__tests__|test|\/test|-test|_test|\.test`),
	},
	{
		ID:          "npm-cache",
		Description: "npm cache directory",
		Pattern:     regexp.MustCompile(`(?i)npm\/_cacache`),
	},
	{
		ID:          "m2-repository",
		Description: "Maven repository directory",
		Pattern:     regexp.MustCompile(`(?i)m2/repository`),
	},
	{
		ID:          "bin",
		Description: "Binary directories like /bin",
		Pattern:     regexp.MustCompile(`(?i)^bin`),
	},
	{
		ID:          "sbin",
		Description: "Binary directories like /sbin",
		Pattern:     regexp.MustCompile(`(?i)^sbin`),
	},
	{
		ID:          "usr-bin",
		Description: "Binary directories under /usr/bin",
		Pattern:     regexp.MustCompile(`(?i)^usr/bin`),
	},
	{
		ID:          "usr-sbin",
		Description: "Binary directories under /usr/sbin",
		Pattern:     regexp.MustCompile(`(?i)^usr/sbin`),
	},
	{
		ID:          "usr-games",
		Description: "Game binaries under /usr/games",
		Pattern:     regexp.MustCompile(`(?i)^usr/games`),
	},
	{
		ID:          "usr-local-bins",
		Description: "Directories under /usr/local",
		Pattern:     regexp.MustCompile(`(?i)^usr/local/(?:bin|lib|sbin|bundle\/gems|share\/man\/|app)`),
	},
	{
		ID:          "usr-lib-gems",
		Description: "Ruby gems paths under /usr/lib/gems",
		Pattern:     regexp.MustCompile(`(?i)^usr/lib/gems`),
	},
	{
		ID:          "usr-src-wordpress",
		Description: "WordPress source paths under /usr/src",
		Pattern:     regexp.MustCompile(`(?i)^usr/src/wordpress`),
	},
	{
		ID:          "usr-lib",
		Description: "Libraries and binaries under /usr/lib",
		Pattern:     regexp.MustCompile(`(?i)^usr/lib`),
	},
	{
		ID:          "proc",
		Description: "System directory /proc",
		Pattern:     regexp.MustCompile(`(?i)^proc`),
	},
	{
		ID:          "sys",
		Description: "System directory /sys",
		Pattern:     regexp.MustCompile(`(?i)^sys`),
	},
	{
		ID:          "dev",
		Description: "System directory /dev",
		Pattern:     regexp.MustCompile(`(?i)^dev`),
	},
	{
		ID:          "run",
		Description: "System directory /run",
		Pattern:     regexp.MustCompile(`(?i)^run`),
	},
	{
		ID:          "boot",
		Description: "System directory /boot",
		Pattern:     regexp.MustCompile(`(?i)^boot`),
	},
	{
		ID:          "snap",
		Description: "System directory /boot",
		Pattern:     regexp.MustCompile(`(?i)^snap`),
	},
	{
		ID:          "lib32-64-x32",
		Description: "System libraries under /lib for various architectures",
		Pattern:     regexp.MustCompile(`(?i)^lib(32|64|x32)`),
	},
	{
		ID:          "usr-lib",
		Description: "User libraries and executables under /usr/lib",
		Pattern:     regexp.MustCompile(`(?i)(?:\./)?usr/lib(?:32|64|x32|exec)?`),
	},
	{
		ID:          "tests",
		Description: "Avoid test files and paths",
		Pattern:     regexp.MustCompile(`(^(?i)test|\/test|-test|_test|\.test)`),
	},
	{
		ID:          "examples",
		Description: "Avoid example files and paths", // e.g. https://github.com/boto/botocore/blob/develop/botocore/data/organizations/2016-11-28/examples-1.json
		Pattern:     regexp.MustCompile(`example`),
	},
	{
		ID:          "vendor",
		Description: "Vendor dirs",
		Pattern:     regexp.MustCompile(`\/vendor\/`),
	},
	{
		ID:          "snake-oil",
		Description: "Some Snake Oil Shit",
		Pattern:     regexp.MustCompile(`(?i)private\/ssl-cert-snakeoil\.key`),
	},
	{
		ID:          "aws-lib",
		Description: "Some AWS CLI",
		Pattern:     regexp.MustCompile(`(?i)dist\/awscli\/botocore\/`),
	},
	{
		ID:          "java-lib",
		Description: "Some Java Lis",
		Pattern:     regexp.MustCompile(`(?i)\/openjdk-[\d.]+\/`),
	},
	{
		ID:          "locale-dir",
		Description: "Locales directory contains locales file",
		Pattern:     regexp.MustCompile(`\/locales?\/`),
	},
}
