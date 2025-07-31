package deps

import (
	"bufio"
	"bytes"
	"log"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

// extractPackageLockDependencies extracts top-level dependencies from package-lock.json structure
func extractPackageLockDependencies(data map[string]interface{}) []Dependency {
	var deps []Dependency

	if packages, ok := data["packages"].(map[string]interface{}); ok {
		// Iterate through the packages
		for name, details := range packages {
			if name == "" {
				// Handle the root entry (project itself)
				if rootDetails, ok := details.(map[string]interface{}); ok {
					// Check for "dependencies" key in the root
					if dependencies, exists := rootDetails["dependencies"].(map[string]interface{}); exists {
						for depName, depVersion := range dependencies {
							if versionStr, ok := depVersion.(string); ok {
								deps = append(deps, Dependency{Name: depName, Version: versionStr})
							}
						}
					}
				}
			}
			// else {
			// 	// Handle other entries (nested dependencies)
			// 	if detailMap, ok := details.(map[string]interface{}); ok {
			// 		if version, exists := detailMap["version"].(string); exists {
			// 			// Extract package name from path, usually after "node_modules/"
			// 			packageName := strings.TrimPrefix(name, "node_modules/")
			// 			deps = append(deps, Dependency{Name: packageName, Version: version})
			// 		}
			// 	}
			// }
		}
	}

	return deps
}

// extractPackageName processes the package name to remove quotes and version constraints.
func extractPackageName(line string) string {
	// Strip surrounding quotes.
	line = strings.Trim(line, "\"")
	// Split by '@' and take the part before the '@'.
	parts := strings.Split(line, "@")
	if len(parts) > 2 {
		return "@" + parts[1]
	}
	return parts[0]
}

// extractYarnLockDependencies extracts dependencies from yarn.lock content.
func extractYarnLockDependencies(content *[]byte) []Dependency {
	var deps []Dependency

	// Define regex patterns for package names and versions.
	packageNameRegex := regexp.MustCompile(`^"([^"]+)"|^([^"\s][^"]*$)`)
	packageVersionRegex := regexp.MustCompile(`^\s{2}version "([^"]+)"`)

	scanner := bufio.NewScanner(bytes.NewReader(*content))
	var packageName string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "#") {
			continue
		}

		// Match package name lines.
		if match := packageNameRegex.FindStringSubmatch(line); match != nil {
			packageName = ""              // Reset current package names
			for _, m := range match[1:] { // Check both capturing groups.
				if m != "" {
					// Handle multiple package names separated by commas.
					names := strings.Split(m, ", ")[0]
					packageName = extractPackageName(names)
				}
			}
		}

		// Match version lines.
		if match := packageVersionRegex.FindStringSubmatch(line); match != nil {
			version := match[1]

			// Append each current package name with the extracted version.
			deps = append(deps, Dependency{Name: packageName, Version: version})
			packageName = "" // Reset for the next set of packages.
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning yarn.lock file: %v", err)
	}

	return deps
}

// extractGemfileLockMainDependencies parses the Gemfile.lock content to extract main dependencies.
func extractGemfileLockMainDependencies(content *[]byte) []Dependency {
	var deps []Dependency

	scanner := bufio.NewScanner(bytes.NewReader(*content))

	// Indicate when we are inside the GEM specs section.
	inGemSpecsSection := false

	// Read through each line in the Gemfile.lock file.
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the start of the GEM specs section.
		if strings.HasPrefix(line, "GEM") {
			inGemSpecsSection = true
			continue
		}

		// Detect the start of the specs subsection.
		if inGemSpecsSection && strings.TrimSpace(line) == "specs:" {
			inGemSpecsSection = true
			continue
		}

		// End of the GEM specs section.
		if inGemSpecsSection && strings.TrimSpace(line) == "" {
			break
		}

		// Process lines within the specs subsection for main dependencies.
		if inGemSpecsSection && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
			// Extract the gem name and version.
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[0], " ")
				version := strings.Trim(parts[1], "()")
				deps = append(deps, Dependency{Name: name, Version: version})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning Gemfile.lock file: %v", err)
	}

	return deps
}
