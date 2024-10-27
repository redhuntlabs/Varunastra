package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Devang-Solanki/RedHunt/Varunastra/config"
	"github.com/Devang-Solanki/RedHunt/Varunastra/docker"

	"github.com/alecthomas/kong"
)

// handleScan processes the scan command.
func handleScan(cli config.CLI, regexDB config.RegexDB, excludedPatterns config.ExcludedPatterns) {
	var scanMap config.ScanMap
	// Process scans
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

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}

	imageName := cli.Target

	// Process each image
	err := docker.ProcessImage(imageName, scanMap, regexDB, excludedPatterns)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Scanning completed.")

	var finalOutput docker.FinalOutput
	finalOutput.Target = imageName

	data, _ := json.MarshalIndent(finalOutput, "", "  ")
	fmt.Println(string(data))
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