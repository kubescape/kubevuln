package process_request

import (
	"bytes"
	"fmt"

	// "ca-vuln-scan/catypes"
	"encoding/json"
	"log"
	"time"

	"net/http"
	"os"

	wssc "github.com/armosec/capacketsgo/apis"
	sysreport "github.com/armosec/capacketsgo/system-reports/datastructures"

	cs "github.com/armosec/capacketsgo/containerscan"
)

var ociClient OcimageClient
var eventRecieverURL string
var cusGUID string
var printPostJSON string

func init() {
	ociClient.endpoint = os.Getenv("OCIMAGE_URL")
	if len(ociClient.endpoint) == 0 {
		log.Fatal("Must configure OCIMAGE_URL")
	}
	eventRecieverURL = os.Getenv("EVENT_RECEIVER_URL")
	if len(eventRecieverURL) == 0 {
		log.Fatal("Must configure EVENT_RECEIVER_URL")
	}
	cusGUID = os.Getenv("CA_CUSTOMER_GUID")
	if len(cusGUID) == 0 {
		log.Fatal("Must configure CA_CUSTOMER_GUID")
	}
	printPostJSON = os.Getenv("PRINT_POST_JSON")
}

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

func (oci *OcimageClient) GetContainerImage(scanCmd *wssc.WebsocketScanCommand) (*OciImage, error) {
	image, err := oci.Image(scanCmd)
	if err != nil {
		return nil, err
	}
	return image, nil
}

func postScanResultsToEventReciever(imagetag string, wlid string, containerName string, layersList *cs.LayersList) error {

	log.Printf("posting to event reciever image %s wlid %s", imagetag, wlid)
	timestamp := int64(time.Now().Unix())
	final_report := cs.ScanResultReport{
		CustomerGUID:  cusGUID,
		ImgTag:        imagetag,
		ImgHash:       "",
		WLID:          wlid,
		ContainerName: containerName,
		Timestamp:     timestamp,
		Layers:        *layersList,
	}

	payload, err := json.Marshal(final_report)
	if err != nil {
		log.Printf("fail convert to json")
		return err
	}

	if printPostJSON != "" {
		log.Printf("printPostJSON:")
		log.Printf("%v", string(payload))
	}

	resp, err := http.Post(eventRecieverURL+"/k8s/containerScan", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("fail posting to event reciever image %s wlid %s", imagetag, wlid)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 299 < resp.StatusCode {
		log.Printf("clair post to event reciever failed with %d", resp.StatusCode)
		return err
	}
	log.Printf("posting to event reciever image %s wlid %s finished seccessfully", imagetag, wlid)

	return nil
}

func GetScanResult(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, error) {

	ociImage, err := ociClient.Image(scanCmd)
	if err != nil {
		log.Printf("Not able to get image %s", err)
		return nil, err
	}

	manifest, err := ociImage.GetManifest()
	if err != nil {
		log.Printf("Not able to get manifest %s", err)
		return nil, err
	}

	packageManager, err := CreatePackageHandler(ociImage)
	if err != nil {
		log.Printf("Package handler cannot be initialized %s", err)
		// return nil, err
	}

	scanresultlayer, err := GetClairScanResultsByLayerV4(manifest, packageManager, scanCmd.ImageTag)
	if err != nil {
		log.Printf("GetClairScanResultsByLayer failed with err %v to image %s", err, scanCmd.ImageTag)
		return nil, err
	}

	return scanresultlayer, nil
}

func ProcessScanRequest(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, error) {
	report := &sysreport.BaseReport{
		CustomerGUID: os.Getenv("CA_CUSTOMER_GUID"),
		Reporter:     "ca-vuln-scan",
		Status:       sysreport.JobStarted,
		ActionName:   fmt.Sprintf("vuln scan:: scanning wlid:%v , container:%v image: %v", scanCmd.Wlid, scanCmd.ContainerName, scanCmd.ImageTag),
		ActionID:     "1",
		ActionIDN:    1,
	}
	report.SendAsRoutine([]string{}, true)
	// NewBaseReport(cusGUID, )
	result, err := GetScanResult(scanCmd)
	if err != nil {
		report.SendError(err, true, true)
		return nil, err
	}
	report.SendStatus(sysreport.JobSuccess, true)
	report.SendAction(fmt.Sprintf("vuln scan:notifying event receiver about %v scan", scanCmd.ImageTag), true)
	err = postScanResultsToEventReciever(scanCmd.ImageTag, scanCmd.Wlid, scanCmd.ContainerName, result)
	if err != nil {
		report.SendError(fmt.Errorf("vuln scan:notifying event receiver about %v scan failed due to %v", scanCmd.ImageTag, err.Error()), true, true)
	} else {
		report.SendStatus(sysreport.JobSuccess, true)
	}
	return result, nil
}
