package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

func main() {

	Init()

	var workerwg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		workerwg.Add(1)
		go worker(&workerwg)
	}

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}
	imageName := os.Args[1]

	// Process each image
	processImage(imageName)

	log.Println("Scanning completed.")

	finalOutput.Target = imageName

	data, _ := json.MarshalIndent(finalOutput, "", "  ")
	fmt.Println(string(data))

}
