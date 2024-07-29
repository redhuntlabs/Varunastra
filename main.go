package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func main() {

	if len(regexData) < 1 {
		if !serializeRegexDB() {
			log.Fatalln("Error serializing regex data. Exiting...")
		}
	}

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}
	imageName := os.Args[1]

	// Process each image
	log.Println("Starting Scan for Image:", imageName)
	processImage(imageName)

	log.Println("Scanning completed.")

	finalop.Target = imageName
	finalop.Data = finalResult
	finalop.Version = "1.0"
	data, _ := json.MarshalIndent(finalop, "", "  ")
	fmt.Println(string(data))

}
