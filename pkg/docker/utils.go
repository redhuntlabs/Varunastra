package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/redhuntlabs/Varunastra/pkg/config"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/exp/rand"
	"mvdan.cc/xurls/v2"
)

// AddDomainsAndUrls appends new domains and URLs to assets
func (a *Assets) AddDomainsAndUrls(content string) {
	domains := GetSubdomainsAndDomains(content)
	a.Domains = append(a.Domains, domains...)

	urls := GetUrls(content)
	a.Urls = append(a.Urls, urls...)

}

// MakeUniqueDomains removes duplicate domains and subdomains
func (a *Assets) MakeUniqueDomains() {
	uniqueDomains := make(map[string]map[string]struct{})

	for _, domain := range a.Domains {
		if _, exists := uniqueDomains[domain.Domain]; !exists {
			uniqueDomains[domain.Domain] = make(map[string]struct{})
		}
		for _, sub := range domain.Subdomains {
			uniqueDomains[domain.Domain][sub] = struct{}{}
		}
	}

	a.Domains = make([]SubAndDom, 0, len(uniqueDomains))
	for domainName, subdomainSet := range uniqueDomains {
		subdomains := make([]string, 0, len(subdomainSet))
		for sub := range subdomainSet {
			subdomains = append(subdomains, sub)
		}
		a.Domains = append(a.Domains, SubAndDom{Domain: domainName, Subdomains: subdomains})
	}
}

// MakeUniqueUrls removes duplicate URLs
func (a *Assets) MakeUniqueUrls() {
	uniqueUrls := make(map[string]struct{})
	for _, url := range a.Urls {
		uniqueUrls[url] = struct{}{}
	}

	a.Urls = make([]string, 0, len(uniqueUrls))
	for url := range uniqueUrls {
		a.Urls = append(a.Urls, url)
	}
}

func GetUrls(content string) []string {
	rxStrict := xurls.Strict()
	urls := rxStrict.FindAllString(content, -1) // []string{"http://foo.com/"}
	return urls
}

func GetSubdomainsAndDomains(content string) []SubAndDom {
	pattern := `[A-Za-z0-9](?:[A-Za-z0-9.-]){2,63}\.[A-Za-z0-9]{2,18}`
	regex := regexp.MustCompile(pattern)

	subdomains := regex.FindAllString(content, -1)

	domainMap := make(map[string][]string)

	for _, subdomain := range subdomains {
		domain, _ := publicsuffix.DomainFromListWithOptions(
			publicsuffix.DefaultList,
			subdomain,
			&publicsuffix.FindOptions{
				IgnorePrivate: true,
			},
		)

		domain = strings.ToLower(domain)
		subdomain = strings.ToLower(subdomain)

		if domain != "" && subdomain != domain {
			// Check if the domain resolves successfully with custom DNS resolvers
			if resolveDomain(domain) {
				domainMap[domain] = append(domainMap[domain], subdomain)
			}
		}
	}

	var filteredDomains []SubAndDom
	for domain, subdomains := range domainMap {
		data := SubAndDom{Domain: domain, Subdomains: subdomains}
		filteredDomains = append(filteredDomains, data)
	}

	return filteredDomains
}

// Function to resolve a domain using custom resolvers
func resolveDomain(domain string) bool {
	// Seed the random number generator
	rand.Seed(uint64(time.Now().UnixNano()))

	// Pick a random resolver from the list
	randomResolver := resolvers[rand.Intn(len(resolvers))]

	// Set up a custom DNS resolver using the selected DNS server
	dnsResolver := &net.Resolver{
		PreferGo: true, // Use Go's built-in DNS resolver first (can be set to false to prioritize system DNS)
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", randomResolver+":53")
		},
	}

	// Perform the DNS lookup
	_, err := dnsResolver.LookupHost(context.Background(), domain)
	return err == nil // Return true if the domain resolves successfully, false otherwise
}

// fetchTagsFromRegistry fetches available tags for an image from the specified Docker registry
func fetchTagsFromRegistry(imageName string, registry name.Registry) ([]string, error) {

	// Determine the registry URL and formulate the API URL
	var apiURL string
	switch registry.Name() {
	case "index.docker.io":
		if strings.HasPrefix(imageName, "index.docker.io/") {
			registryPrefix := "index.docker.io/"
			imageName = strings.TrimPrefix(imageName, registryPrefix)
		}
		repo := strings.Split(imageName, ":")[0]
		repoParts := strings.Split(repo, "/")
		if len(repoParts) == 1 {
			// For official Docker Hub images
			apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/library/%s/tags", repo)
		} else {
			// For other Docker Hub images
			apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/%s/%s/tags", repoParts[0], repoParts[1])
		}
	case "ghcr.io":
		// For GitHub Container Registry images
		if strings.HasPrefix(imageName, "ghcr.io/") {
			// Check for 'public.ecr.aws' registry
			registryPrefix := "ghcr.io/"
			imageName = strings.TrimPrefix(imageName, registryPrefix)
		}

		apiURL = fmt.Sprintf("https://ghcr.io/v2/%s/tags/list", imageName)
	case "gcr.io":
		// For Google Container Registry images
		// apiURL = fmt.Sprintf("https://gcr.io/v2/%s/tags/list", repo)
		if strings.HasPrefix(imageName, "gcr.io/") {
			// Check for 'public.ecr.aws' registry
			registryPrefix := "gcr.io/"
			imageName = strings.TrimPrefix(imageName, registryPrefix)
		}

		apiURL = fmt.Sprintf("https://gcr.io/v2/%s/tags/list", imageName)

	case "public.ecr.aws":
		if strings.HasPrefix(imageName, "public.ecr.aws/") {
			// Check for 'public.ecr.aws' registry
			registryPrefix := "public.ecr.aws/"
			imageName = strings.TrimPrefix(imageName, registryPrefix)
		}
		// For Amazon ECR images, the API requires a different endpoint
		apiURL = fmt.Sprintf("https://public.ecr.aws/v2/%s/tags/list", imageName)
	default:
		return nil, fmt.Errorf("unsupported registry: %s", registry)
	}

	// Get the token if needed (for GCR and AWS ECR)
	token, err := getAuthToken(registry.Name(), imageName)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch tags: received status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response based on the registry
	switch registry.Name() {
	case "index.docker.io":
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
	case "ghcr.io":
		// Parse the GitHub Container Registry response
		var ghTagsResponse struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}

		if err := json.Unmarshal(body, &ghTagsResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return ghTagsResponse.Tags, nil
	case "gcr.io":
		// Parse the Google Container Registry response

		var gcrTagsResponse struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}

		err := json.Unmarshal(body, &gcrTagsResponse)
		if err != nil {
			log.Fatalf("Error unmarshalling JSON: %v", err)
		}

		if err := json.Unmarshal(body, &gcrTagsResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return gcrTagsResponse.Tags, nil
	case "public.ecr.aws":
		// Parse the Amazon ECR response

		// TagResponse represents the structure of the response for image tags.
		var tagResponse struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}

		if err := json.Unmarshal(body, &tagResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return tagResponse.Tags, nil
	}

	return nil, fmt.Errorf("unsupported registry: %s", registry)
}

// getAuthToken retrieves an authentication token for the specified registry
func getAuthToken(registry string, imageName string) (string, error) {
	switch registry {
	case "gcr.io":
		var token string

		tokenUrl := fmt.Sprintf("https://gcr.io/v2/token?scope=repository:%s:pull", imageName)

		resp, httpErr := http.Get(tokenUrl)
		defer resp.Body.Close()

		if httpErr == nil && resp.StatusCode == 200 {
			var result map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&result)
			token = result["token"]
		} else {
			return "", fmt.Errorf("failed to retrive token for gcr.io")
		}
		return token, nil
	case "ghcr.io":
		var token string

		tokenUrl := fmt.Sprintf("https://ghcr.io/token?service=ghcr.io&scope=repository:%s:pull", imageName)

		resp, httpErr := http.Get(tokenUrl)
		defer resp.Body.Close()

		if httpErr == nil && resp.StatusCode == 200 {
			var result map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&result)
			token = result["token"]
		} else {
			return "", fmt.Errorf("failed to retrive token for ghcr.io")
		}
		return token, nil
	case "public.ecr.aws":
		// Implement AWS ECR token retrieval
		// You would typically use the AWS SDK to get an ECR authorization token here
		// This is a placeholder; replace with actual implementation.
		var token string

		resp, httpErr := http.Get("https://public.ecr.aws/token")
		defer resp.Body.Close()

		if httpErr == nil && resp.StatusCode == 200 {
			var result map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&result)
			token = result["token"]
		} else {
			return "", fmt.Errorf("failed to retrive token for aws")
		}
		return token, nil
	}
	return "", nil
}

// Function to determine if a layer is compressed or uncompressed and to get the appropriate hash or diff ID
func getLayerInfo(layer v1.Layer) (v1.Hash, error) {
	// Determine if the layer is compressed or uncompressed
	isCompressed, err := isCompressedLayer(layer)
	if err != nil {
		return v1.Hash{}, err
	}

	// Get the appropriate identifier
	if isCompressed {
		digest, err := layer.Digest()
		if err != nil {
			return v1.Hash{}, err
		}
		return digest, nil
	} else {
		diffID, err := layer.DiffID()
		if err != nil {
			return v1.Hash{}, err
		}
		return diffID, nil
	}
}

// Function to check if the layer is compressed or uncompressed
func isCompressedLayer(layer v1.Layer) (bool, error) {
	// Use reflection to check if the layer is of the type that has the UncompressedLayer method
	layerType := reflect.TypeOf(layer)
	_, uncompressed := layerType.Elem().FieldByName("UncompressedLayer")
	return !uncompressed, nil
}

func checkDupEntry(secret, typestr string, path string, finalResult []SecretIssue) bool {
	for _, dxresult := range finalResult {
		// log.Println(strings.Trim(strings.Trim(dxresult.Secret, "`"), "\""), secret)
		if dxresult.Type == typestr && strings.Trim(strings.Trim(dxresult.Secret, "`"), "\"") == secret && dxresult.Path == path {
			// if dxresult.Type == typestr && dxresult.Secret == secret {
			return true
		}
	}
	return false
}

// RemoveDuplicates modifies the slice directly by removing duplicates.
func RemoveDuplicates(issues *[]SecretIssue) {
	// Create a map to keep track of unique entries
	uniqueMap := make(map[string]SecretIssue)

	// Create a new slice to hold the unique issues
	var uniqueIssues []SecretIssue

	// Loop through the slice and store unique SecretIssue entries in the map
	for _, issue := range *issues {
		// Create a key based on Type, Secret, and Path (you can adjust this as necessary)
		key := fmt.Sprintf("%s|%s", issue.Secret, issue.Path)

		// If the key doesn't exist in the map, add it
		if _, exists := uniqueMap[key]; !exists {
			uniqueMap[key] = issue
			uniqueIssues = append(uniqueIssues, issue) // Append to the new slice
		}
	}

	// Replace the original slice with the unique entries
	*issues = uniqueIssues
}

// secretScanner scans the content for secrets and returns any issues found
func secretScanner(path string, content *[]byte, id interface{}, regexDB []config.RegexDB) ([]SecretIssue, error) {
	var finalResult []SecretIssue
	var wg sync.WaitGroup
	var place string

	switch v := id.(type) {
	case v1.Hash:
		id = v.String()
		place = "Layer"
	case string:
		id = v
		place = "History"
	default:
		return nil, fmt.Errorf("unsupported type: %T", id)
	}

	var mu sync.Mutex // mutex to protect finalResult

	for _, regex := range regexDB {
		wg.Add(1)
		go func(r config.RegexDB) {
			defer wg.Done()

			x := r.Pattern.FindAllSubmatch(*content, -1)
			if len(x) > 0 {
				for _, y := range x {
					if len(y) > 1 && r.ID != "" {
						if checkDupEntry(string(y[1]), r.ID, path, finalResult) {
							continue
						}
					}

					var kissue SecretIssue
					kissue.Issue = fmt.Sprintf("Secret Leaked in Docker %s %s", place, id)
					kissue.Path = path
					kissue.Type = r.ID
					kissue.Secret = string(y[0])

					mu.Lock()
					finalResult = append(finalResult, kissue)
					mu.Unlock()

					log.Print("\n")
					log.Printf("Secrets found -> Type: %s | Secret: %s | On Path: %s", r.ID, string(y[0]), path)
				}
			}
		}(regex)
	}

	wg.Wait()

	if len(finalResult) != 0 {
		return finalResult, nil
	}

	return nil, fmt.Errorf("no secrets found in %s", id)
}
