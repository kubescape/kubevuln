package main

import (
	colim "ca-vuln-scan/goroutinelimits"
	"ca-vuln-scan/process_request"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	wssc "asterix.cyberarmor.io/cyberarmor/capacketsgo/apis"
)

var goroutineLimit *colim.CoroutineGuardian

func startScanImage(imagetag string, wlid string, containerName string) {
	log.Printf("Scan request to image %s is put on processing queue", imagetag)

	goroutineLimit.Wait()
	go func() {
		process_request.ProcessScanRequest(imagetag, wlid, containerName)
		goroutineLimit.Release()
	}()

}

func scanImage(w http.ResponseWriter, req *http.Request) {
	var WebsocketScan wssc.WebsocketScanCommand

	if req.Method == http.MethodPost {
		err := json.NewDecoder(req.Body).Decode(&WebsocketScan)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("fail decode json from web socket, error %v", err)
			return
		}
		if WebsocketScan.ImageTag == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("image tag is missing")
			return
		}
		if WebsocketScan.IsScanned == true {
			w.WriteHeader(http.StatusAccepted)
			log.Printf("this image already scanned")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "scan request accepted\n")

		startScanImage(WebsocketScan.ImageTag, WebsocketScan.Wlid, WebsocketScan.ContainerName)

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}

}

func main() {
	goroutineLimit, _ = colim.CreateCoroutineGuardian(colim.MAX_VULN_SCAN_ROUTINS)

	uri := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.WebsocketScanCommandPath
	log.Printf("uri %v", uri)
	http.HandleFunc(uri, scanImage)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
