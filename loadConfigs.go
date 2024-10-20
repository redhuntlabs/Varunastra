package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v2"
)

func initRegex(configFilePath string) error {
	// Read the JSON file
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Unmarshal JSON data into a map
	if err := json.Unmarshal(data, &regexes); err != nil {
		return fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	var regexDB RegexDB
	var dbs []RegexDB

	for title, pattern := range regexes {
		regexDB.ID = title
		regexDB.Pattern = regexp.MustCompile(pattern)
		dbs = append(dbs, regexDB)
	}

	regexStore = dbs
	return nil
}

func LoadConfig() error {
	log.Printf("Checking if config file exist")
	// Get the home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Define the full path to the config directory
	configPath := filepath.Join(homeDir, configDir)

	// Check if the config directory exists, create it if not
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return err
		}
	}

	// Define the full path to the config directory
	configPath = filepath.Join(homeDir, configDir, configFile)

	// Check if the config file exists, download if not
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := downloadFile(configURL, configPath); err != nil {
			return err
		}
	}

	// Read the config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	// Parse the YAML configuration
	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return err
	}

	// Check if regex files path is provided
	if config.RegexFiles.Path == "" {
		return fmt.Errorf("regex_files path is not defined in config")
	}

	regexPath := filepath.Join(homeDir, config.RegexFiles.Path)
	// Call initRegex with the regex file path
	err = initRegex(regexPath)
	if err != nil {
		return err
	}

	// Initialize regex from blacklisted_patterns
	for _, bp := range config.BlacklistedPatterns {
		re, err := regexp.Compile(bp.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex in blacklisted_patterns %s: %v", bp.Pattern, err)
		}
		excludedPatterns = append(excludedPatterns, re)
	}

	return nil
}

func downloadFile(url, filepath string) error {
	log.Println("Downloading default config from: devanghacks.in/varunastra/config.yaml")
	// Send HTTP GET request
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file: %s", resp.Status)
	}

	// Read the response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Write the data to the specified file
	err = os.WriteFile(filepath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
