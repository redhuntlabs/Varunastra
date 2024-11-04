package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	"github.com/Devang-Solanki/Varunastra/pkg/docker"

	"github.com/alecthomas/kong"
)

// handleScan processes the scan command.
func handleScan(cli config.CLI, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns) {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}

	scanMap := config.CreateScanMap(cli.Scans)

	imageName := cli.Target

	// Process each image
	output, err := docker.ProcessImage(imageName, scanMap, regexDB, excludedPatterns, cli.All)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Scanning completed.")

	data, _ := json.MarshalIndent(output, "", "  ")
	config.HandleOutput(data, cli)

}

func main() {

	var cli config.CLI
	ctx := kong.Parse(&cli)

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

	regexDB, excludedPatterns, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Process the command based on the context
	handleScan(cli, regexDB, excludedPatterns)
	ctx.Exit(0)
}
