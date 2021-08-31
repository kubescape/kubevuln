package main

import (
	colim "ca-vuln-scan/goroutinelimits"
	"ca-vuln-scan/process_request"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	wssc "github.com/armosec/capacketsgo/apis"
)

var goroutineLimit *colim.CoroutineGuardian

func startScanImage(scanCmd *wssc.WebsocketScanCommand) {
	log.Printf("Scan request to image %s is put on processing queue", scanCmd.ImageTag)

	goroutineLimit.Wait()
	go func() {
		process_request.ProcessScanRequest(scanCmd)
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

		startScanImage(&WebsocketScan)

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}

}

func main() {
	process_request.CreateAnchoreResourcesDirectoryAndFiles()
	flag.Parse()
	scanRoutinslimitStr := os.Getenv("CA_MAX_VULN_SCAN_ROUTINS")
	scanRoutinslimit := colim.MAX_VULN_SCAN_ROUTINS
	if len(scanRoutinslimitStr) != 0 {
		if i, err := strconv.Atoi(scanRoutinslimitStr); err == nil {
			scanRoutinslimit = i
		}
	}
	goroutineLimit, _ = colim.CreateCoroutineGuardian(scanRoutinslimit)

	uri := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.WebsocketScanCommandPath
	log.Printf("uri %v", uri)
	http.HandleFunc(uri, scanImage)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
