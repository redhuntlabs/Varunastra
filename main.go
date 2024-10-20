package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/alecthomas/kong"
)

// handleScan processes the scan command.
func handleScan(cli CLI) {
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

	var workerwg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		workerwg.Add(1)
		go worker(&workerwg)
	}

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}

	imageName := cli.Target

	// Process each image
	err := processImage(imageName)
	if err != nil {
		log.Fatalln(err)
	}

	close(taskChannel)
	workerwg.Wait()

	log.Println("Scanning completed.")

	finalOutput.Target = imageName

	data, _ := json.MarshalIndent(finalOutput, "", "  ")
	fmt.Println(string(data))
}

func main() {

	var cli CLI
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

	err := LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Process the command based on the context
	handleScan(cli)
	ctx.Exit(0)
}
