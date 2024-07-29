package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// processImage processes a single Docker image
func processImage(imageName string) {
	// Determine if image is local or remote
	isLocalFile := strings.HasSuffix(imageName, ".tar")

	var img v1.Image
	var err error

	if isLocalFile {
		img, err = tarball.ImageFromPath(imageName, nil)
		if err != nil {
			log.Printf("Failed to load local image %s: %v", imageName, err)
			return
		}
	} else {
		ref, err := name.ParseReference(imageName)
		if err != nil {
			log.Printf("Failed to parse image reference %s: %v", imageName, err)
			return
		}

		// Try to get the remote image
		img, err = remote.Image(ref)
		if err != nil {
			log.Printf("Failed to retrieve remote image %s: %v", imageName, err)
			// Try fetching available tags if latest doesn't work
			if strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":") {
				tags, err := fetchTagsFromDockerHub(imageName)
				if err != nil {
					log.Printf("Failed to fetch tags for image %s: %v", imageName, err)
					return
				}
				if len(tags) > 0 {
					// Retry with the first available tag
					log.Printf("Retrying with the first available tag: %s", tags[0])
					imageName = strings.Split(imageName, ":")[0] + ":" + tags[0]
					ref, err = name.ParseReference(imageName)
					if err != nil {
						log.Printf("Failed to parse image reference %s: %v", imageName, err)
						return
					}
					img, err = remote.Image(ref)
					if err != nil {
						log.Printf("Failed to retrieve remote image %s: %v", imageName, err)
						return
					}
				} else {
					log.Printf("No available tags found for image %s", imageName)
					return
				}
			} else {
				return
			}
		}
	}

	// Process the image layers and history entries
	processLayers(img)

	// Scan environment variables for secrets
	scanEnvVars(img)

	// Function call to process history
	processHistory(img)

	// Delete the image after processing
	deleteDockerImage(imageName)
}

// processLayers processes the layers of a Docker image
func processLayers(img v1.Image) {
	layers, err := img.Layers()
	if err != nil {
		log.Printf("Failed to get image layers: %v", err)
		return
	}

	for _, layer := range layers {
		processLayer(layer)
	}
}

// processLayer reads and processes the content of a single image layer
func processLayer(layer v1.Layer) {
	r, err := layer.Uncompressed()
	if err != nil {
		log.Printf("Failed to get uncompressed layer: %v", err)
		return
	}
	defer r.Close()

	// Get the layer's digest for logging
	digest, err := layer.Digest()
	if err != nil {
		log.Printf("Failed to get layer digest: %v", err)
		return
	}
	log.Printf("Processing layer with digest: %s", digest)

	// Read the layer as a tarball
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of tar archive
		}
		if err != nil {
			log.Printf("Failed to read layer tar: %v", err)
			continue
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg || isExcluded(header.Name) {
			continue
		}

		// Read file content
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			log.Printf("Failed to read file %s: %v", header.Name, err)
			continue
		}
		content := buf.Bytes()
		// Scan the file content for secrets
		secretScanner(header.Name, &content, digest)
	}
}

// processHistory scans the history of a Docker image for potential secrets
func processHistory(img v1.Image) {
	config, err := img.ConfigFile()
	if err != nil {
		log.Printf("Failed to get image config: %v", err)
		return
	}

	log.Printf("Processing history entries")

	for i, entry := range config.History {
		// Check the commands executed in each layer
		if entry.CreatedBy != "" {
			createdByContent := []byte(entry.CreatedBy)
			secretScanner(fmt.Sprintf("History entry %d", i), &createdByContent, v1.Hash{Algorithm: "nil"})
		}
	}
}

// scanEnvVars scans environment variables in the image config for potential secrets
func scanEnvVars(img v1.Image) {
	configFile, err := img.ConfigFile()
	if err != nil {
		log.Printf("Failed to get image config file: %v", err)
		return
	}

	for _, envVar := range configFile.Config.Env {
		envVarContent := []byte(envVar)
		secretScanner("ENV", &envVarContent, configFile.RootFS.DiffIDs[0])
	}
}

// deleteDockerImage deletes the Docker image using Docker API
func deleteDockerImage(imageName string) {
	// Create a Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}

	// Remove the Docker image
	_, err = cli.ImageRemove(context.Background(), imageName, image.RemoveOptions{Force: true})
	if err != nil {
		log.Printf("Failed to remove Docker image %s: %v", imageName, err)
	} else {
		log.Printf("Successfully removed Docker image: %s", imageName)
	}
}
