package main

import (
	"log"
	"strings"
	"sync"
)

func worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range taskChannel {

		if scanMap["secrets"] {
			finalResult, err := secretScanner(task.Path, task.Content, task.ID)
			if err != nil {
				if !strings.Contains(err.Error(), "no secrets found in") {
					log.Printf("Error scanning secrets: %s", err)
				}
			} else {
				finalOutput.Secrets = append(finalOutput.Secrets, finalResult...)
			}
		}
	}
}

func queueTask(path string, content *[]byte, id interface{}, imageName string) {
	task := SecretScanTask{
		Path:      path,
		Content:   content,
		ID:        id,
		ImageName: imageName,
	}
	taskChannel <- task
}
