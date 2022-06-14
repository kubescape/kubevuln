package main

import (
	"ca-vuln-scan/process_request"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/armosec/utils-k8s-go/probes"
	"github.com/golang/glog"

	wssc "github.com/armosec/armoapi-go/apis"
)

type task func(payload interface{}) (interface{}, error)

type taskData struct {
	cb            task
	payload       interface{}
	returnError   error
	returnPayload interface{}
}

var taskChan chan taskData
var isReadinessReady bool = false

func startScanImage(scanCmdInterface interface{}) (interface{}, error) {
	scanCmd := scanCmdInterface.(*wssc.WebsocketScanCommand)

	log.Printf("ProcessScanRequest for jobid %v/%v %s image: %s starting", scanCmd.ParentJobID, scanCmd.JobID, scanCmd.Wlid, scanCmd.ImageTag)

	_, err := process_request.ProcessScanRequest(scanCmd)
	if err != nil {
		log.Printf("ProcessScanRequest for jobid %v/%v %s image: %s failed due to: %s", scanCmd.ParentJobID, scanCmd.JobID, scanCmd.Wlid, scanCmd.ImageTag, err.Error())
	}

	return nil, nil
}

func serverReadyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusAccepted)
	} else if req.Method == http.MethodPost {
		bytes, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("serverReadyHandler: fail decode post req, error %v", err)
			return
		}
		data := string(bytes)
		if data == process_request.DB_IS_READY {
			isReadinessReady = true
			w.WriteHeader(http.StatusAccepted)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func commandDBHandler(w http.ResponseWriter, req *http.Request) {

	var err error
	var innerDBCommand wssc.DBCommand

	if req.Method == http.MethodPost {
		err = json.NewDecoder(req.Body).Decode(&innerDBCommand)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("commandDBHandler: fail decode json, error %v", err)
			return
		}
		for op, data := range innerDBCommand.Commands {
			td := taskData{}
			switch {
			case op == "updateDB":
				td.cb = process_request.StartUpdateDB
				td.payload = data
				taskChan <- td
				w.WriteHeader(http.StatusAccepted)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}
}

func scanImageHandler(w http.ResponseWriter, req *http.Request) {
	var WebsocketScan wssc.WebsocketScanCommand

	if req.Method == http.MethodPost {
		err := json.NewDecoder(req.Body).Decode(&WebsocketScan)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("fail decode json from web socket, error %v", err)
			return
		}
		if WebsocketScan.ImageTag == "" && WebsocketScan.ImageHash == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("image tag and image hash are missing")
			return
		}
		if WebsocketScan.IsScanned {
			w.WriteHeader(http.StatusAccepted)
			log.Printf("the image %s already scanned", WebsocketScan.ImageTag)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "scan request accepted\n")
		// Backend aggregation depends on this report!!!
		// don't change any parameter before checking with BE side first!!!!
		report := &sysreport.BaseReport{
			CustomerGUID: os.Getenv("CA_CUSTOMER_GUID"),
			Reporter:     "ca-vuln-scan",
			Status:       sysreport.JobStarted,
			Target:       fmt.Sprintf("vuln scan:: scanning wlid: %v ,containerName: %v imageTag: %v imageHash: %s", WebsocketScan.Wlid, WebsocketScan.ContainerName, WebsocketScan.ImageTag, WebsocketScan.ImageHash),
			ActionID:     "1",
			ActionIDN:    1,
			ActionName:   "vuln scan",
			JobID:        WebsocketScan.JobID,
			ParentAction: WebsocketScan.ParentJobID,
			Details:      "Inqueueing",
		}
		report.SendAsRoutine([]string{}, true)
		// End of Backend must not change report
		td := taskData{
			cb:      startScanImage,
			payload: &WebsocketScan,
		}

		log.Printf("Scan request to image %s is put on processing queue", WebsocketScan.ImageTag)
		taskChan <- td

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}
}

func taskChannelHandler(taskChan <-chan taskData) {
	for td := range taskChan {
		td.cb(td.payload)
	}
}

func main() {
	process_request.CreateAnchoreResourcesDirectoryAndFiles()
	flag.Parse()
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()

	pkgcautils.LoadConfig("", true)

	scanURI := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.WebsocketScanCommandPath
	DBCommandURI := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.DBCommandPath
	ServerReadyURI := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.ServerReady

	log.Printf("uri %v", scanURI)

	taskChan = make(chan taskData, 100)
	go taskChannelHandler(taskChan)
	go process_request.HandleAnchoreDBUpdate(DBCommandURI, ServerReadyURI)
	http.HandleFunc(scanURI, scanImageHandler)
	http.HandleFunc(DBCommandURI, commandDBHandler)
	http.HandleFunc(ServerReadyURI, serverReadyHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func displayBuildTag() {
	imageVersion := "local build"
	dat, err := ioutil.ReadFile("./build_number.txt")
	if err == nil {
		imageVersion = string(dat)
	} else {
		dat, err = ioutil.ReadFile("./build_date.txt")
		if err == nil {
			imageVersion = fmt.Sprintf("%s, date: %s", imageVersion, string(dat))
		}
	}
	glog.Infof("Image version: %s", imageVersion)
}
