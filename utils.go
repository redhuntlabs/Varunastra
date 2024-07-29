package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	REGEXFILE = "regexes.json"
)

type (
	FinalOutput struct {
		Target  string       `json:"target"`
		Data    []FoundIssue `json:"data"`
		Version string
	}
	FoundIssue struct {
		Issue  string  `json:"issue"`
		Path   string  `json:"asset"`
		Type   string  `json:"title"`
		Secret string  `json:"variant_description"`
		Digest v1.Hash `json:"layer_digest"`
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

var (
	finalop     FinalOutput
	finalResult []FoundIssue
	regexData   map[string]string
	mu          sync.Mutex
)

// func GenerateCustomID() string {
// 	currentTime := time.Now().UnixNano()
// 	randomNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))
// 	return fmt.Sprintf("%d-%d", currentTime, randomNumber)
// }

func fetchJSONFile(filename string) (string, error) {
	url := "https://d3exj2ftp2qys5.cloudfront.net/" + REGEXFILE

	resp, err := http.Get(url)
	if err != nil {
		return filename, err
	}
	defer resp.Body.Close()

	file, err := os.Create(filename)
	if err != nil {
		return filename, err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return filename, err
	}
	return filename, err
}

func serializeRegexDB() bool {
	dbdata, err := ioutil.ReadFile(REGEXFILE)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	if err := json.Unmarshal(dbdata, &regexData); err != nil {
		log.Println(err.Error())
		return false
	}
	return true
}

func checkDupEntry(secret, typestr string, path string) bool {
	for _, dxresult := range finalResult {
		// log.Println(strings.Trim(strings.Trim(dxresult.Secret, "`"), "\""), secret)
		if dxresult.Type == typestr && strings.Trim(strings.Trim(dxresult.Secret, "`"), "\"") == secret && dxresult.Path == path {
			// if dxresult.Type == typestr && dxresult.Secret == secret {
			return true
		}
	}
	return false
}

func secretScanner(path string, content *[]byte, digest v1.Hash) {
	for typerex, regexstr := range regexData {
		demoRex := regexp.MustCompile(regexstr)
		x := demoRex.FindAllSubmatch(*content, -1)
		if len(x) > 0 {
			for _, y := range x {
				if len(y) > 1 && typerex != "" {
					if checkDupEntry(string(y[1]), typerex, path) {
						continue
					}
				}
				var kissue FoundIssue
				kissue.Issue = "Secret Leaked in Docker Container"
				kissue.Path = path
				if digest.Algorithm != "nil" {
					kissue.Digest = digest
				}

				kissue.Type = typerex
				kissue.Secret = string(y[0])

				// Acquire lock before writing to the map
				mu.Lock()
				finalResult = append(finalResult, kissue)
				mu.Unlock()

				log.Print("\n")
				log.Printf("Secrets found -> Type: %s | Secret: %s | On Path: %s", typerex, string(y[0]), path)
			}
		}
	}
}

// fetchTagsFromDockerHub fetches available tags for an image from Docker Hub
func fetchTagsFromDockerHub(imageName string) ([]string, error) {
	repo := strings.Split(imageName, ":")[0]
	repoParts := strings.Split(repo, "/")

	// Formulate the Docker Hub API URL
	var apiURL string
	if len(repoParts) == 1 {
		// For official Docker Hub images
		apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/library/%s/tags", repo)
	} else {
		// For other Docker Hub images
		apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/%s/%s/tags", repoParts[0], repoParts[1])
	}

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch tags: received status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tagsResponse struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &tagsResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	tags := make([]string, 0, len(tagsResponse.Results))
	for _, result := range tagsResponse.Results {
		tags = append(tags, result.Name)
	}

	return tags, nil
}

// isExcluded checks if a file path starts with any of the excluded directories
func isExcluded(filePath string) bool {

	// Define a list of directories to exclude
	var excludedDirs = []string{
		// System Directories
		"proc",
		"sys",
		"dev",
		"run",
		"boot",
		"lib",
		"lib32",
		"lib64",
		"libx32",
		"usr/lib",
		"usr/lib32",
		"usr/lib64",
		"usr/libx32",
		"usr/libexec",
		"usr/share",
		"usr/share/locale",

		// Temporary and Cache Directories
		"tmp",
		"var/tmp",
		"var/cache",
		"var/run",

		// Package and Build Directories
		"usr/share/doc",
		"usr/share/man",
		"usr/include",
		"usr/src",
		"var/lib",
		"node_modules",
		"dist-packages",
		"vendor",
		"__pycache__",
		"pip-cache",
		".cargo",
		"__tests__",

		// Binaries and Executables
		"bin",
		"/sbin",
		"usr/bin",
		"usr/sbin",
		"usr/games",
		"usr/local/bin",
		"usr/local/sbin",
	}

	for _, dir := range excludedDirs {
		// Check if the file path starts with the excluded directory path
		if strings.HasPrefix(filePath, dir) {
			return true
		}
	}
	return false
}
