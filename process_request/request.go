package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/armosec/utils-go/httputils"
	"github.com/golang/glog"

	"github.com/hashicorp/go-multierror"

	"os"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	"k8s.io/utils/strings/slices"

	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
)

const (
	maxBodySize  int = 30000
	ReporterName     = "ca-vuln-scan"
)

var eventReceiverURL string
var customerGUID string
var printPostJSON string
var ReportErrorsChan chan error
var ReporterHttpClient httputils.IHttpClient

func init() {
	eventReceiverURL = os.Getenv(EventReceiverUrlEnvironmentVariable)
	if len(eventReceiverURL) == 0 {
		glog.Fatalf("Must configure either %s", EventReceiverUrlEnvironmentVariable)
	}

	// TODO: pass mock client in case of empty URL
	ReporterHttpClient = &http.Client{}

	customerGUID = os.Getenv(CustomerGuidEnvironmentVariable)
	if len(customerGUID) == 0 {
		glog.Fatalf("Must configure %s", CustomerGuidEnvironmentVariable)
	}
	printPostJSON = os.Getenv(PrintResultsJsonEnvironmentVariable)

	ReportErrorsChan = make(chan error)
	go func() {
		for err := range ReportErrorsChan {
			if err != nil {
				glog.Errorf("failed to send job report due to ERROR: %s", err.Error())
			}
		}
	}()
}

func postScanResultsToEventReciever(scanCmd *wssc.WebsocketScanCommand, imagetag, imageHash string, wlid string, containerName string, layersList *cs.LayersList, listOfBash []string, preparedLayers map[string]cs.ESLayer) error {

	glog.Infof("posting to event receiver image %s wlid %s", imagetag, wlid)
	timestamp := int64(time.Now().Unix())

	finalReport := cs.ScanResultReport{
		CustomerGUID:             customerGUID,
		ImgTag:                   imagetag,
		ImgHash:                  imageHash,
		WLID:                     wlid,
		ContainerName:            containerName,
		Timestamp:                timestamp,
		Layers:                   *layersList,
		ListOfDangerousArtifcats: listOfBash,
		Session:                  scanCmd.Session,
		Designators: armotypes.PortalDesignator{
			Attributes: map[string]string{},
		},
	}
	if val, ok := scanCmd.Args[armotypes.AttributeRegistryName]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeRegistryName] = val.(string)
	}

	if val, ok := scanCmd.Args[armotypes.AttributeRepository]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeRepository] = val.(string)
	}

	if val, ok := scanCmd.Args[armotypes.AttributeTag]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeTag] = val.(string)
	}

	if val, ok := scanCmd.Args[armotypes.AttributeSensor]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeSensor] = val.(string)
	}
	//complete designators info
	finalDesignators, _ := finalReport.GetDesignatorsNContext()
	finalReport.Designators = *finalDesignators

	glog.Infof("session: %v\n===\n", finalReport.Session)
	flatVuln := finalReport.ToFlatVulnerabilities()
	flatVuln = fillExtraLayerData(preparedLayers, flatVuln)
	//split vulnerabilities to chunks
	chunksChan, totalVulnerabilities := httputils.SplitSlice2Chunks(flatVuln, maxBodySize, 10)
	//send report(s)
	scanID := finalReport.AsFNVHash()
	sendWG := &sync.WaitGroup{}
	errChan := make(chan error, 10)
	//get the first chunk
	firstVulnerabilitiesChunk := <-chunksChan
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	//send the summary and the first chunk in one or two reports according to the size
	nextPartNum := sendSummaryAndVulnerabilities(finalReport, totalVulnerabilities, scanID, firstVulnerabilitiesChunk, errChan, sendWG)
	firstVulnerabilitiesChunk = nil
	//if not all vulnerabilities got into the first chunk
	if totalVulnerabilities != firstChunkVulnerabilitiesCount {
		//send the rest of the vulnerabilities - error channel will be closed when all vulnerabilities are sent
		sendVulnerabilitiesRoutine(chunksChan, scanID, finalReport, errChan, sendWG, totalVulnerabilities, firstChunkVulnerabilitiesCount, nextPartNum)
	} else {
		//only one chunk will be sent so need to close the error channel when it is done
		go func(wg *sync.WaitGroup, errorChan chan error) {
			//wait for summary post request to end
			wg.Wait()
			//close the error channel
			close(errorChan)
		}(sendWG, errChan)
	}
	//collect post report errors if occurred
	var err error
	for e := range errChan {
		err = multierror.Append(err, e)
	}
	return err
}

func sendVulnerabilitiesRoutine(chunksChan <-chan []cs.CommonContainerVulnerabilityResult, scanID string, final_report cs.ScanResultReport, errChan chan error, sendWG *sync.WaitGroup, totalVulnerabilities int, firstChunkVulnerabilitiesCount int, nextPartNum int) {
	go func(scanID string, final_report cs.ScanResultReport, errorChan chan<- error, sendWG *sync.WaitGroup, expectedVulnerabilitiesSum int, partNum int) {
		sendVulnerabilities(chunksChan, partNum, expectedVulnerabilitiesSum, scanID, final_report, errorChan, sendWG)
		//wait for all post request to end (including summary report)
		sendWG.Wait()
		//no more post requests - close the error channel
		close(errorChan)
	}(scanID, final_report, errChan, sendWG, totalVulnerabilities-firstChunkVulnerabilitiesCount, nextPartNum)
}
func fillExtraLayerData(data map[string]cs.ESLayer, vulns []cs.CommonContainerVulnerabilityResult) []cs.CommonContainerVulnerabilityResult {
	for i := range vulns {
		for y := range vulns[i].Layers {
			if l, ok := data[vulns[i].Layers[y].LayerHash]; ok {
				if vulns[i].Layers[y].LayerInfo == nil {
					vulns[i].Layers[y].LayerInfo = &cs.LayerInfo{}
				}
				vulns[i].Layers[y].CreatedBy = l.CreatedBy
				vulns[i].Layers[y].CreatedTime = l.CreatedTime
				vulns[i].Layers[y].LayerOrder = l.LayerOrder
			}

		}
	}
	return vulns
}

func sendVulnerabilities(chunksChan <-chan []cs.CommonContainerVulnerabilityResult, partNum int, expectedVulnerabilitiesSum int, scanID string, final_report cs.ScanResultReport, errorChan chan<- error, sendWG *sync.WaitGroup) {
	//post each vulnerabilities chunk in a different report
	chunksVulnerabilitiesCount := 0
	for vulnerabilities := range chunksChan {
		chunksVulnerabilitiesCount += len(vulnerabilities)
		postResultsAsGoroutine(&cs.ScanResultReportV1{
			PaginationInfo:  wssc.PaginationMarks{ReportNumber: partNum, IsLastReport: chunksVulnerabilitiesCount == expectedVulnerabilitiesSum},
			Vulnerabilities: vulnerabilities,
			ContainerScanID: scanID,
			Timestamp:       final_report.Timestamp,
			Designators:     final_report.Designators,
		}, final_report.ImgTag, final_report.WLID, errorChan, sendWG)
		partNum++
	}

	//verify that all vulnerabilities received and sent
	if chunksVulnerabilitiesCount != expectedVulnerabilitiesSum {
		errorChan <- fmt.Errorf("error while splitting vulnerabilities chunks, expected " + strconv.Itoa(expectedVulnerabilitiesSum) +
			" vulnerabilities but received " + strconv.Itoa(chunksVulnerabilitiesCount))
	}
}

func sendSummaryAndVulnerabilities(report cs.ScanResultReport, totalVulnerabilities int, scanID string, firstVulnerabilitiesChunk []cs.CommonContainerVulnerabilityResult, errChan chan<- error, sendWG *sync.WaitGroup) (nextPartNum int) {
	//get the first chunk
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	//prepare summary report
	nextPartNum = 0
	summaryReport := &cs.ScanResultReportV1{
		PaginationInfo:  wssc.PaginationMarks{ReportNumber: nextPartNum},
		Summary:         report.Summarize(),
		ContainerScanID: scanID,
		Timestamp:       report.Timestamp,
		Designators:     report.Designators,
	}
	//if size of summary + first chunk does not exceed max size
	if httputils.JSONSize(summaryReport)+httputils.JSONSize(firstVulnerabilitiesChunk) <= maxBodySize {
		//then post the summary report with the first vulnerabilities chunk
		summaryReport.Vulnerabilities = firstVulnerabilitiesChunk
		//if all vulnerabilities got into the first chunk set this as the last report
		summaryReport.PaginationInfo.IsLastReport = totalVulnerabilities == firstChunkVulnerabilitiesCount
		//first chunk sent (or is nil) so set to nil
		firstVulnerabilitiesChunk = nil
	} else {
		//first chunk is not included in the summary, so if there are vulnerabilities to send set the last part to false
		summaryReport.PaginationInfo.IsLastReport = firstChunkVulnerabilitiesCount != 0
	}
	//send the summary report
	postResultsAsGoroutine(summaryReport, report.ImgTag, report.WLID, errChan, sendWG)
	//free memory
	summaryReport = nil
	nextPartNum++
	//send the first chunk if it was not sent yet (because of summary size)
	if firstVulnerabilitiesChunk != nil {
		postResultsAsGoroutine(&cs.ScanResultReportV1{
			PaginationInfo:  wssc.PaginationMarks{ReportNumber: nextPartNum, IsLastReport: totalVulnerabilities == firstChunkVulnerabilitiesCount},
			Vulnerabilities: firstVulnerabilitiesChunk,
			ContainerScanID: scanID,
			Timestamp:       report.Timestamp,
			Designators:     report.Designators,
		}, report.ImgTag, report.WLID, errChan, sendWG)
		nextPartNum++
	}
	return nextPartNum
}

func postResultsAsGoroutine(report *cs.ScanResultReportV1, imagetag string, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(report *cs.ScanResultReportV1, imagetag string, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
		defer wg.Done()
		postResults(report, imagetag, wlid, errorChan)
	}(report, imagetag, wlid, errorChan, wg)

}
func postResults(report *cs.ScanResultReportV1, imagetag string, wlid string, errorChan chan<- error) {
	payload, err := json.Marshal(report)
	if err != nil {
		glog.Error("fail convert to json")
		errorChan <- err
		return
	}
	if printPostJSON != "" {
		glog.Info("printPostJSON:")
		glog.Infof("%v", string(payload))
	}

	resp, err := http.Post(eventReceiverURL+"/k8s/v2/containerScan?"+armotypes.CustomerGuidQuery+"="+report.Designators.Attributes[armotypes.AttributeCustomerGUID], "application/json", bytes.NewReader(payload))
	if err != nil {
		glog.Errorf("fail posting to event receiver image %s wlid %s", imagetag, wlid)
		errorChan <- err
		return
	}
	defer resp.Body.Close()
	body, err := httputils.HttpRespToString(resp)
	if err != nil {
		glog.Errorf("Vulnerabilities post to event receiver failed with error:%s response body: %s", err.Error(), body)
		errorChan <- err
		return
	}
	glog.Infof("posting to event receiver image %s wlid %s finished successfully response body: %s", imagetag, wlid, body) // systest dependent
}
func RemoveFile(filename string) {
	err := os.Remove(filename)
	if err != nil {
		glog.Errorf("Error removing file %s error:%s", filename, err.Error())
	}
}

func GetScanResult(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, []string, map[string]cs.ESLayer, error) {
	filteredResultsChan := make(chan []string)

	scanresultlayer, preparedLayers, err := GetAnchoreScanResults(scanCmd)
	if err != nil {
		glog.Errorf("getAnchoreScanResults returned an error:%s", err.Error())
		return nil, nil, nil, err
	}

	filteredResult := <-filteredResultsChan

	return scanresultlayer, filteredResult, preparedLayers, nil
}

func ProcessScanRequest(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, error) {
	report := sysreport.NewBaseReport(
		os.Getenv(CustomerGuidEnvironmentVariable),
		ReporterName,
		os.Getenv(EventReceiverUrlEnvironmentVariable),
		ReporterHttpClient,
	)
	report.Status = sysreport.JobStarted
	report.Target = fmt.Sprintf("vuln scan:: scanning wlid: %v , container: %v imageTag: %v imageHash: %s", scanCmd.Wlid, scanCmd.ContainerName, scanCmd.ImageTag, scanCmd.ImageHash)
	report.ActionID = "2"
	report.ActionIDN = 2
	report.ActionName = "vuln scan"
	report.JobID = scanCmd.JobID
	report.ParentAction = scanCmd.ParentJobID
	report.Details = "Dequeueing"

	if len(scanCmd.JobID) != 0 {
		report.SetJobID(scanCmd.JobID)
	}
	if scanCmd.LastAction > 0 {
		report.SetActionIDN(scanCmd.LastAction + 1)
	}

	jobID := report.GetJobID()
	if !slices.Contains(scanCmd.Session.JobIDs, jobID) {
		scanCmd.Session.JobIDs = append(scanCmd.Session.JobIDs, jobID)
	}
	report.SendAsRoutine(true, ReportErrorsChan)

	result, bashList, preparedLayers, err := GetScanResult(scanCmd)
	if err != nil {
		report.SendError(err, true, true, ReportErrorsChan)
		return nil, err
	}

	report.SendStatus(sysreport.JobSuccess, true, ReportErrorsChan)

	report.SendAction(fmt.Sprintf("vuln scan:notifying event receiver about %v scan", scanCmd.ImageTag), true, ReportErrorsChan)

	err = postScanResultsToEventReciever(scanCmd, scanCmd.ImageTag, scanCmd.ImageHash, scanCmd.Wlid, scanCmd.ContainerName, result, bashList, preparedLayers)
	if err != nil {
		report.SendError(fmt.Errorf("vuln scan:notifying event receiver about %v scan failed due to %v", scanCmd.ImageTag, err.Error()), true, true, ReportErrorsChan)
	} else {
		report.SendStatus(sysreport.JobDone, true, ReportErrorsChan)

	}
	return result, nil
}
