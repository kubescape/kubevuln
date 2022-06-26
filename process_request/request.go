package process_request

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	armoUtils "github.com/armosec/utils-go/httputils"
	"github.com/golang/glog"

	"github.com/hashicorp/go-multierror"

	// "ca-vuln-scan/catypes"

	"os"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	"k8s.io/utils/strings/slices"

	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
)

var ociClient OcimageClient
var eventRecieverURL string
var cusGUID string
var printPostJSON string

//
func init() {
	ociClient.endpoint = os.Getenv("OCIMAGE_URL")
	if len(ociClient.endpoint) == 0 {
		ociClient.endpoint = os.Getenv("CA_OCIMAGE_URL")
		if len(ociClient.endpoint) == 0 {
			glog.Warning("OCIMAGE_URL/CA_OCIMAGE_URL is not configured- some features might not work, please install OCIMAGE to get more features")
		}
	}

	eventRecieverURL = os.Getenv("CA_EVENT_RECEIVER_HTTP")
	if len(eventRecieverURL) == 0 {
		glog.Fatal("Must configure either CA_EVENT_RECEIVER_HTTP")
	}

	cusGUID = os.Getenv("CA_CUSTOMER_GUID")
	if len(cusGUID) == 0 {
		glog.Fatal("Must configure CA_CUSTOMER_GUID")
	}
	printPostJSON = os.Getenv("PRINT_POST_JSON")
}

/* unused to be deleted
func getContainerImageManifest(scanCmd *wssc.WebsocketScanCommand) (*OciImageManifest, error) {
	oci := OcimageClient{endpoint: "http://localhost:8080"}
	image, err := oci.Image(scanCmd)
	if err != nil {
		return nil, err
	}
	manifest, err := image.GetManifest()
	if err != nil {
		return nil, err
	}
	return manifest, nil
}
*/

func (oci *OcimageClient) GetContainerImage(scanCmd *wssc.WebsocketScanCommand) (*OciImage, error) {
	image, err := oci.Image(scanCmd)
	if err != nil {
		return nil, err
	}
	return image, nil
}

const maxBodySize int = 30000

func postScanResultsToEventReciever(scanCmd *wssc.WebsocketScanCommand, imagetag, imageHash string, wlid string, containerName string, layersList *cs.LayersList, listOfBash []string) error {

	glog.Infof("posting to event reciever image %s wlid %s", imagetag, wlid)
	timestamp := int64(time.Now().Unix())

	final_report := cs.ScanResultReport{
		CustomerGUID:             cusGUID,
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
		final_report.Designators.Attributes[armotypes.AttributeRegistryName] = val.(string)
	}

	if val, ok := scanCmd.Args[armotypes.AttributeRepository]; ok {
		final_report.Designators.Attributes[armotypes.AttributeRepository] = val.(string)
	}

	if val, ok := scanCmd.Args[armotypes.AttributeTag]; ok {
		final_report.Designators.Attributes[armotypes.AttributeTag] = val.(string)
	}

	//complete designators info
	finalDesignators, _ := final_report.GetDesignatorsNContext()
	final_report.Designators = *finalDesignators

	glog.Infof("session: %v\n===\n", final_report.Session)
	//split vulnerabilities to chunks
	chunksChan, totalVulnerabilities := armoUtils.SplitSlice2Chunks(final_report.ToFlatVulnerabilities(), maxBodySize, 10)
	//send report(s)
	scanID := final_report.AsFNVHash()
	sendWG := &sync.WaitGroup{}
	errChan := make(chan error, 10)
	//get the first chunk
	firstVulnerabilitiesChunk := <-chunksChan
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	firstVulnerabilitiesChunk = nil
	//send the summary and the first chunk in one or two reports according to the size
	nextPartNum := sendSummaryAndVulnerabilities(final_report, totalVulnerabilities, scanID, firstVulnerabilitiesChunk, errChan, sendWG)
	//if not all vulnerabilities got into the first chunk
	if totalVulnerabilities != firstChunkVulnerabilitiesCount {
		//send the rest of the vulnerabilities
		sendVulnerabilitiesRoutine(chunksChan, scanID, final_report, errChan, sendWG, totalVulnerabilities, firstChunkVulnerabilitiesCount, nextPartNum)
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
	nextPartNum = 1
	summaryReport := &cs.ScanResultReportV1{
		PaginationInfo:  wssc.PaginationMarks{ReportNumber: nextPartNum},
		Summary:         report.Summarize(),
		ContainerScanID: scanID,
		Timestamp:       report.Timestamp,
		Designators:     report.Designators,
	}
	//if size of summary + first chunk does not exceed max size
	if armoUtils.JSONSize(summaryReport)+armoUtils.JSONSize(firstVulnerabilitiesChunk) <= maxBodySize {
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
	resp, err := http.Post(eventRecieverURL+"/k8s/containerScanV1?"+armotypes.CustomerGuidQuery+"="+report.Designators.Attributes[armotypes.AttributeCustomerGUID], "application/json", bytes.NewReader(payload))
	if err != nil {
		glog.Errorf("fail posting to event receiver image %s wlid %s", imagetag, wlid)
		errorChan <- err
		return
	}
	defer resp.Body.Close()
	body, err := armoUtils.HttpRespToString(resp)
	if err != nil {
		glog.Errorf("Vulnerabilities post to event receiver failed with error:%s response body: %s", err.Error(), body)
		errorChan <- err
		return
	}
	glog.Infof("posting to event receiver image %s wlid %s finished successfully response body: %s", imagetag, wlid, body)
}

func RemoveFile(filename string) {
	err := os.Remove(filename)
	if err != nil {
		glog.Errorf("Error removing file %s error:%s", filename, err.Error())
	}
}

func GetScanResult(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, []string, error) {
	filteredResultsChan := make(chan []string)

	/*
		This code get list of executables that can be dangerous
	*/
	if ociClient.endpoint != "" {
		ociImage, err := ociClient.Image(scanCmd)
		if err != nil {
			glog.Errorf("unable to get image %s", err)
			go func() {
				glog.Info("skipping dangerous executables enrichment")
				filteredResultsChan <- nil
			}()
			// return nil, nil, err
		} else {
			go func() {
				listOfPrograms := []string{
					"bin/sh", "bin/bash", "sbin/sh", "bin/ksh", "bin/tcsh", "bin/zsh", "usr/bin/scsh", "bin/csh", "bin/busybox", "usr/bin/kubectl", "usr/bin/curl",
					"usr/bin/wget", "usr/bin/ssh", "usr/bin/ftp", "usr/share/gdb", "usr/bin/nmap", "usr/share/nmap", "usr/bin/tcpdump", "usr/bin/ping",
					"usr/bin/netcat", "usr/bin/gcc", "usr/bin/busybox", "usr/bin/nslookup", "usr/bin/host", "usr/bin/dig", "usr/bin/psql", "usr/bin/swaks",
				}
				filteredResult := []string{}

				directoryFilesInBytes, err := ociImage.GetFiles(listOfPrograms, true, true)
				if err != nil {
					glog.Errorf("can not get filelist from ocimage due to %s", err.Error())
					filteredResultsChan <- nil
					return
				}
				rand.Seed(time.Now().UnixNano())
				randomNum := rand.Intn(100)
				filename := "/tmp/file" + fmt.Sprint(randomNum) + ".tar.gz"
				permissions := 0644
				ioutil.WriteFile(filename, *directoryFilesInBytes, fs.FileMode(permissions))

				reader, err := os.Open(filename)
				if err != nil {
					glog.Errorf("can not open file : %s error:%s", filename, err.Error())
					filteredResultsChan <- nil
					return
				}
				defer reader.Close()
				defer RemoveFile(filename)

				tarReader := tar.NewReader(reader)
				buf := new(strings.Builder)
				for {
					currentFile, err := tarReader.Next()
					if err == io.EOF {
						break
					}

					if currentFile.Name == "symlinkMap.json" {
						_, err := io.Copy(buf, tarReader)
						if err != nil {
							glog.Error("can not parse symlinkMap.json file")
							filteredResultsChan <- nil
							return
						}

					}
				}
				var fileInJson map[string]string
				err = json.Unmarshal([]byte(buf.String()), &fileInJson)
				if err != nil {
					glog.Errorf("failed to marshal file %s. error:%s", filename, err.Error())
					filteredResultsChan <- nil
					return
				}

				for _, element := range listOfPrograms {
					if element, ok := fileInJson[element]; ok {
						filteredResult = append(filteredResult, element)
					}
				}
				filteredResultsChan <- filteredResult
			}()
		}
	} else {
		go func() {
			glog.Info("skipping dangerous executables enrichment")
			filteredResultsChan <- nil
		}()

	}
	/*
		End of dangerous execuatables collect code
	*/

	scanresultlayer, err := GetAnchoreScanResults(scanCmd)
	if err != nil {
		glog.Errorf("getAnchoreScanResults returned an error:%s", err.Error())
		return nil, nil, err
	}

	filteredResult := <-filteredResultsChan

	return scanresultlayer, filteredResult, nil
}

func ProcessScanRequest(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, error) {
	report := &sysreport.BaseReport{
		CustomerGUID: os.Getenv("CA_CUSTOMER_GUID"),
		Reporter:     "ca-vuln-scan",
		Status:       sysreport.JobStarted,
		Target: fmt.Sprintf("vuln scan:: scanning wlid: %v , container: %v imageTag: %v imageHash: %s", scanCmd.Wlid,
			scanCmd.ContainerName, scanCmd.ImageTag, scanCmd.ImageHash),
		ActionID:     "2",
		ActionIDN:    2,
		ActionName:   "vuln scan",
		JobID:        scanCmd.JobID,
		ParentAction: scanCmd.ParentJobID,
		Details:      "Dequeueing",
	}

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

	report.SendAsRoutine([]string{}, true)
	// NewBaseReport(cusGUID, )
	result, bashList, err := GetScanResult(scanCmd)
	if err != nil {

		report.SendError(err, true, true)
		return nil, err
	}
	report.SendStatus(sysreport.JobSuccess, true)
	report.SendAction(fmt.Sprintf("vuln scan:notifying event receiver about %v scan", scanCmd.ImageTag), true)

	//Benh - dangerous hack

	err = postScanResultsToEventReciever(scanCmd, scanCmd.ImageTag, scanCmd.ImageHash, scanCmd.Wlid, scanCmd.ContainerName, result, bashList)
	if err != nil {
		report.SendError(fmt.Errorf("vuln scan:notifying event receiver about %v scan failed due to %v", scanCmd.ImageTag, err.Error()), true, true)
	} else {
		report.SendStatus(sysreport.JobDone, true)
	}
	return result, nil
}
