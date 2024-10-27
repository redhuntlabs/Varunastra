package docker

import (
	"log"
	"strings"
	"sync"

	"github.com/Devang-Solanki/RedHunt/Varunastra/config"
)

func worker(wg *sync.WaitGroup, output *FinalOutput, scanMap config.ScanMap, regexDB config.RegexDB) {
	defer wg.Done()
	for task := range taskChannel {

		if scanMap["secrets"] {
			finalResult, err := secretScanner(task.Path, task.Content, task.ID, regexDB)
			if err != nil {
				if !strings.Contains(err.Error(), "no secrets found in") {
					log.Printf("Error scanning secrets: %s", err)
				}
			} else {
				output.Secrets = append(output.Secrets, finalResult...)
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
