package config

import (
	"fmt"
	"log"
	"os"
)

func HandleOutput(data []byte, cli CLI) {

	if cli.Output == "" {
		fmt.Println(string(data))
	} else {
		if err := writeOutputToFile(cli, data); err != nil {
			log.Fatalln("Error:", err)
		}
	}
}

func writeOutputToFile(cli CLI, output []byte) error {
	if cli.Output == "" {
		return fmt.Errorf("no output filename specified")
	}

	// Open the file for writing (this will overwrite the file if it exists)
	file, err := os.Create(cli.Output) // Use os.OpenFile if you want to append instead
	if err != nil {
		return fmt.Errorf("failed to create or open file %s: %v", cli.Output, err)
	}
	defer file.Close()

	// Write the data to the file
	if _, err := file.Write(output); err != nil {
		return fmt.Errorf("failed to write data to file %s: %v", cli.Output, err)
	}

	return nil
}
