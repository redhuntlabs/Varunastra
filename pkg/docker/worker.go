package docker

import (
	"log"
	"strings"
	"sync"

	"github.com/redhuntlabs/Varunastra/pkg/config"
)

func worker(wg *sync.WaitGroup, output *FinalOutput, scanMap config.ScanMap, regexDB []config.RegexDB, taskChannel <-chan SecretScanTask, assets *Assets) {
	defer wg.Done()
	var secrets []SecretIssue
	for task := range taskChannel {
		if scanMap["secrets"] {
			finalResult, err := secretScanner(task.Path, task.Content, task.ID, regexDB)
			if err != nil {
				if !strings.Contains(err.Error(), "no secrets found in") {
					log.Printf("Error scanning secrets: %s", err)
				}
			} else {
				secrets = append(secrets, finalResult...)
			}
		}

		if scanMap["assets"] {
			assets.AddDomainsAndUrls(string(*task.Content))
		}
	}

	output.Secrets = append(output.Secrets, secrets...)

}

func queueTask(path string, content *[]byte, id interface{}, imageName string, taskChannel chan<- SecretScanTask) {

	task := SecretScanTask{
		Path:      path,
		Content:   content,
		ID:        id,
		ImageName: imageName,
	}
	taskChannel <- task
}
