package main

import (
	"encoding/json"
	"html/template"
	"log"
	"os"
	"strings"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	"github.com/Devang-Solanki/Varunastra/pkg/docker"

	"github.com/alecthomas/kong"
)

// handleScan processes the scan command.
func handleScan(cli config.CLI, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns, whitelistedPatterns config.WhitelistedPatterns) {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}

	scanMap := config.CreateScanMap(cli.Scans)

	imageName := cli.Target

	// Process each image
	output, err := docker.ProcessImage(imageName, scanMap, regexDB, excludedPatterns, whitelistedPatterns, cli.All)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Scanning completed.")

	data, _ := json.MarshalIndent(output, "", "  ")
	config.HandleOutput(data, cli)

	if cli.Html != "" {
		log.Println("Generating Report")
		// Step 3: Parse and execute the template with the parsed data
		t, err := template.New("scanReport").Parse(tmpl)
		if err != nil {
			log.Fatal(err)
		}

		// Output to an HTML file (can be stdout or a file)
		file, err := os.Create(cli.Html)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		err = t.Execute(file, output)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("HTML report generated successfully as,", cli.Html)
	}
}

func main() {

	var cli config.CLI

	ctx := kong.Parse(&cli,
		kong.Name("varunastra"),
		kong.Description("Varunastra is a tool designed to detect and assist in mitigating vulnerabilities within Docker images.\n\n- For images hosted on Docker Hub, simply provide the repository name (e.g., `datadog/agent`).\n\n- For images from AWS or GCP, include the full registry URL (e.g., `public.ecr.aws/hashicorp/vault`). \n\nIf no tag is specified in the repository URL, the tool will automatically choose a tag from the available options for scanning. \n\n Note: Domains are resolved via DNS queries, while URLs are extracted using regular expressions without resolution."),
	)

	// Process scans
	scanMap := make(map[string]bool)
	defaultScans := []string{"secrets", "vuln", "assets"}

	if cli.Scans == "" {
		for _, scan := range defaultScans {
			scanMap[scan] = true
		}
	} else {
		scanList := strings.Split(cli.Scans, ",")
		for _, scan := range defaultScans {
			scanMap[scan] = false // Default to false
		}
		for _, scan := range scanList {
			scanMap[scan] = true // Set specified scans to true
		}
	}

	regexDB, excludedPatterns, whitelistedPatterns, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Process the command based on the context
	handleScan(cli, regexDB, excludedPatterns, whitelistedPatterns)
	ctx.Exit(0)
}
