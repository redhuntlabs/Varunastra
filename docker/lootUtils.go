package docker

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"reflect"
	"strings"
	"sync"

	"github.com/Devang-Solanki/RedHunt/Varunastra/config"
	"github.com/Devang-Solanki/RedHunt/Varunastra/deps"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

var (
	output FinalOutput
	scans  config.ScanMap
)

// processImage processes a single Docker image
func ProcessImage(imageName string, scanMap map[string]bool, regexDB config.RegexDB, excludedPatterns config.ExcludedPatterns) (FinalOutput, error) {
	scans = scanMap

	var workerwg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerwg.Add(1)
		go worker(&workerwg, &output, &scans, regexDB)
	}

	log.Println("Starting Scan for Image:", imageName)

	var img v1.Image
	var err error

	isLocalFile := strings.HasSuffix(imageName, ".tar")

	if isLocalFile {
		img, err = tarball.ImageFromPath(imageName, nil)
		if err != nil {
			return FinalOutput{}, fmt.Errorf("failed to load local image %s: %v", imageName, err)
		}
	} else {
		ref, err := name.ParseReference(imageName)
		if err != nil {
			return FinalOutput{}, fmt.Errorf("failed to parse image reference %s: %v", imageName, err)

		}
		// Try to get the remote image
		img, err = remote.Image(ref)
		if err != nil {
			return FinalOutput{}, fmt.Errorf("failed to retrieve remote image %s: %w", imageName, err)
		}
	}

	// Create a WaitGroup to wait for goroutines to complete
	var wg sync.WaitGroup

	// Create an error channel to collect errors from goroutines
	errorCh := make(chan error, 2)

	// Run processLayers in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := processLayers(img, imageName, excludedPatterns); err != nil {
			errorCh <- fmt.Errorf("error processing layers: %w", err)
			return
		}
	}()

	// Run processHistoryAndENV in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := processHistoryAndENV(img, imageName); err != nil {
			errorCh <- fmt.Errorf("error scanning environment variables: %w", err)
			return
		}
	}()

	// Close the error channel once all goroutines are done
	go func() {
		wg.Wait()
		close(errorCh)
	}()

	// Check for any errors from goroutines
	for err := range errorCh {
		return FinalOutput{}, err
	}

	close(taskChannel)
	workerwg.Wait()
	return output, nil
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

// processLayers processes the layers of a Docker image
func processLayers(img v1.Image, imageName string, excludedPatterns config.ExcludedPatterns) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxGoroutines) // Semaphore channel

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get image layers: %w", err)
	}

	for _, layer := range layers {
		key, err := getLayerInfo(layer)
		if err != nil {
			return fmt.Errorf("error getting layer Hash: %s", err)
		}

		sem <- struct{}{} // Acquire a token
		wg.Add(1)         // Increment the WaitGroup counter

		go func(layer v1.Layer, key v1.Hash, imageName string) {
			defer wg.Done()          // Decrement the counter when the goroutine completes
			defer func() { <-sem }() // Release the token

			if err := processLayer(layer, key, imageName, excludedPatterns); err != nil {
				log.Printf("error processing layer: %s", err)
			}
		}(layer, key, imageName)
	}

	wg.Wait() // Wait for all goroutines to finish
	return nil
}

// processLayer reads and processes the content of a single image layer
func processLayer(layer v1.Layer, digest v1.Hash, imageName string, excludedPatterns config.ExcludedPatterns) error {
	log.Println("Scanning Layers:", digest.String())

	// fileSemaphore := make(chan struct{}, 10)

	r, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("failed to get uncompressed layer: %w", err)
	}
	defer r.Close()

	// gitSkip := false

	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of tar archive
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %w", err)
		}

		if header.Typeflag != tar.TypeReg || isExcluded(header.Name, excludedPatterns) {
			continue
		}

		// Handle specific file names directly
		if handleSpecialFiles(header.Name) {
			continue
		}

		// if strings.Contains(header.Name, ".git/") && gitSkip {
		// 	continue
		// }

		// if strings.Contains(header.Name, ".git/HEAD") && scanMap["vuln"] {
		// 	gitSkip = true
		// 	handleGitRepo(header.Name)
		// 	continue
		// }

		err = processFileContent(tr, header, digest, imageName)
		if err != nil {
			log.Printf("Error processing file %s: %s", header.Name, err)
		}

	}

	return nil
}

func processFileContent(tr *tar.Reader, header *tar.Header, digest v1.Hash, imageName string) error {

	// Scan the file content for secrets
	// Check if it's a known dependency file
	if deps.IsKnownDependencyFile(header.Name) && scans["vuln"] {
		return deps.HandleDependencyFile(header.Name, tr, &output)
	}

	if header.Size > maxFileSize {
		// Handle large files by writing to a temp file
		return processLargeFile(tr, header.Name, digest, imageName)
	} else {
		// Handle smaller files directly
		return processSmallFile(tr, header.Name, digest, imageName)
	}
}

// processHistory scans the history of a Docker image for potential secrets
func processHistoryAndENV(img v1.Image, imageName string) error {
	config, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get image config: %w", err)
	}

	for i, entry := range config.History {
		if entry.CreatedBy != "" {
			createdByContent := []byte(entry.CreatedBy)
			queueTask(fmt.Sprintf("history:%d", i), &createdByContent, fmt.Sprintf("history:%d", i), imageName)
		}
	}

	for _, envVar := range config.Config.Env {
		envVarContent := []byte(envVar)
		queueTask("ENV", &envVarContent, config.RootFS.DiffIDs[0], imageName)
	}

	return nil
}
