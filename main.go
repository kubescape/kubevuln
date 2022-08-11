package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/armosec/utils-k8s-go/probes"
	"github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
	"github.com/golang/glog"
	"github.com/kubescape/kubevuln/docs"
	"github.com/kubescape/kubevuln/scanner"

	wssc "github.com/armosec/armoapi-go/apis"
)

type task func(payload interface{}, config *pkgcautils.ClusterConfig) (interface{}, error)

type taskData struct {
	cb      task
	config  *pkgcautils.ClusterConfig
	payload interface{}
}

var taskChan chan taskData

type httpHandler struct {
	config           *pkgcautils.ClusterConfig
	isReadinessReady bool
}

//go:generate swagger generate spec -o ./docs/swagger.yaml
func main() {
	displayBuildTag()

	httpHandlers, err := newHttpHandler()
	if err != nil {
		glog.Fatalf("fail load config, error %v", err)
	}

	if err := scanner.CreateAnchoreResourcesDirectoryAndFiles(); err != nil {
		glog.Fatalf("failed to create anchore resources directory and files, error %v", err)
	}

	go probes.InitReadinessV1(&httpHandlers.isReadinessReady)

	scanURI := fmt.Sprintf("/%s/%s", wssc.WebsocketScanCommandVersion, wssc.WebsocketScanCommandPath)
	DBCommandURI := fmt.Sprintf("/%s/%s", wssc.WebsocketScanCommandVersion, wssc.DBCommandPath)
	ServerReadyURI := fmt.Sprintf("/%s/%s", wssc.WebsocketScanCommandVersion, wssc.ServerReady)
	taskChan = make(chan taskData, 100)

	go taskChannelHandler(taskChan)
	go scanner.HandleAnchoreDBUpdate(DBCommandURI, ServerReadyURI)

	// Set up http listeners
	http.HandleFunc(scanURI, httpHandlers.scanImageHandler)
	http.HandleFunc(DBCommandURI, httpHandlers.commandDBHandler)
	http.HandleFunc(ServerReadyURI, httpHandlers.serverReadyHandler)

	// Set up OpenAPI UI
	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	http.Handle(docs.OpenAPIV2Prefix, openAPIUIHandler)

	// Set up pprof server
	servePprof()

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// newHttpHandlers creates new http handlers for the server
func newHttpHandler() (*httpHandler, error) {
	pathToConfig := os.Getenv(scanner.ConfigEnvironmentVariable) // if empty, will load config from default path
	config, err := pkgcautils.LoadConfig(pathToConfig)
	if err != nil {
		return nil, fmt.Errorf("fail load config, error %v", err)
	}
	return &httpHandler{
		config:           config,
		isReadinessReady: false,
	}, nil
}

func (handler *httpHandler) serverReadyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusAccepted)
	} else if req.Method == http.MethodPost {
		bytes, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			glog.Errorf("serverReadyHandler: fail decode post req, error %v", err)
			return
		}
		data := string(bytes)
		if data == scanner.DbIsReady {
			handler.isReadinessReady = true
			w.WriteHeader(http.StatusAccepted)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func (handler *httpHandler) commandDBHandler(w http.ResponseWriter, req *http.Request) {

	var err error
	var innerDBCommand wssc.DBCommand

	if req.Method == http.MethodPost {
		err = json.NewDecoder(req.Body).Decode(&innerDBCommand)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			glog.Errorf("commandDBHandler: fail decode json, error %v", err)
			return
		}
		for op, data := range innerDBCommand.Commands {
			td := taskData{}
			switch {
			case op == "updateDB":
				td.cb = scanner.StartUpdateDB
				td.config = handler.config
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

func (handler *httpHandler) scanImageHandler(w http.ResponseWriter, req *http.Request) {
	var WebsocketScan wssc.WebsocketScanCommand

	if req.Method == http.MethodPost {
		err := json.NewDecoder(req.Body).Decode(&WebsocketScan)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			glog.Errorf("fail decode json from web socket, error %v", err)
			return
		}
		if WebsocketScan.ImageTag == "" && WebsocketScan.ImageHash == "" {
			w.WriteHeader(http.StatusBadRequest)
			glog.Errorf("image tag and image hash are missing")
			return
		}
		if WebsocketScan.IsScanned {
			w.WriteHeader(http.StatusAccepted)
			glog.Errorf("the image %s already scanned", WebsocketScan.ImageTag)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "scan request accepted\n")
		// Backend aggregation depends on this report!!!
		// don't change any parameter before checking with BE side first!!!!

		report := sysreport.NewBaseReport(
			handler.config.AccountID,
			scanner.ReporterName,
			handler.config.EventReceiverRestURL,
			scanner.ReporterHttpClient,
		)

		report.Status = sysreport.JobStarted
		report.Target = fmt.Sprintf("vuln scan:: scanning wlid: %v ,containerName: %v imageTag: %v imageHash: %s", WebsocketScan.Wlid, WebsocketScan.ContainerName, WebsocketScan.ImageTag, WebsocketScan.ImageHash)
		report.ActionID = "1"
		report.ActionIDN = 1
		report.ActionName = "vuln scan"
		report.JobID = WebsocketScan.JobID
		report.ParentAction = WebsocketScan.ParentJobID
		report.Details = "Inqueueing"

		report.SendAsRoutine(true, scanner.ReportErrorsChan)

		// End of Backend must not change report
		td := taskData{
			cb:      startScanImage,
			config:  handler.config,
			payload: &WebsocketScan,
		}

		glog.Infof("Scan request to image %s is put on processing queue", WebsocketScan.ImageTag)
		taskChan <- td

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}
}

func taskChannelHandler(taskChan <-chan taskData) {
	for td := range taskChan {
		td.cb(td.payload, td.config)
	}
}

func displayBuildTag() {
	flag.Parse()
	glog.Infof("Image version: %s", os.Getenv(scanner.ReleaseBuildTagEnvironmentVariable))
}

func servePprof() {
	go func() {
		// start pprof server -> https://pkg.go.dev/net/http/pprof
		if logger.L().GetLevel() == helpers.DebugLevel.String() {
			logger.L().Info("starting pprof server", helpers.String("port", "6060"))
			logger.L().Error(http.ListenAndServe(":6060", nil).Error())
		}
	}()
}

func startScanImage(scanCmdInterface interface{}, config *pkgcautils.ClusterConfig) (interface{}, error) {
	scanCmd := scanCmdInterface.(*wssc.WebsocketScanCommand)

	glog.Infof("ProcessScanRequest for jobid %v/%v %s image: %s starting", scanCmd.ParentJobID, scanCmd.JobID, scanCmd.Wlid, scanCmd.ImageTag)

	_, err := scanner.ProcessScanRequest(scanCmd, config)
	if err != nil {
		glog.Errorf("ProcessScanRequest for jobid %v/%v %s image: %s failed due to: %s", scanCmd.ParentJobID, scanCmd.JobID, scanCmd.Wlid, scanCmd.ImageTag, err.Error())
	}

	return nil, nil
}
