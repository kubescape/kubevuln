package process_request

import (
	"bytes"
	// "ca-vuln-scan/catypes"
	"encoding/json"
	"log"
	"time"

	"os"
	"net/http"
	cs "asterix.cyberarmor.io/cyberarmor/capacketsgo/containerscan"
)

type ScanResult struct {
	ImageTag   string          `json:"imageTag"`
	ImageHash  string          `json:"imageHash"`
	WorkloadId string          `json:"wlid"`
	Features   *[]ClairFeature `json:"features"`
}

var ociClient OcimageClient
var eventRecieverURL string 
var cusGUID string 

func init() {
	ociClient.endpoint = os.Getenv("OCIMAGE_URL")
	if len(ociClient.endpoint) == 0 {
		log.Fatal("Must configure OCIMAGE_URL")
	}
	eventRecieverURL = os.Getenv("EVENT_RECIEVER_URL")
	if len(eventRecieverURL) == 0 {
		log.Fatal("Must configure EVENT_RECIEVER_URL")
	}
	cusGUID = os.Getenv("CA_CUSTOMER_GUID")
	if len(cusGUID) == 0 {
		log.Fatal("Must configure CA_CUSTOMER_GUID")
	}

}

func getContainerImageManifest(containerImageRefernce string) (*OciImageManifest, error) {
	oci := OcimageClient{endpoint: "http://localhost:8080"}
	image, err := oci.Image(containerImageRefernce)
	if err != nil {
		return nil, err
	}
	manifest, err := image.GetManifest()
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (oci *OcimageClient) GetContainerImage(containerImageRefernce string) (*OciImage, error) {
	image, err := oci.Image(containerImageRefernce)
	if err != nil {
		return nil, err
	}
	return image, nil
}

func postScanResultsToEventReciever(imagetag string, wlid string, layersList *cs.LayersList) error{

	log.Printf("posting to event reciever image %s wlid %s", imagetag, wlid)
	timestamp := int64(time.Now().Unix())
	final_report := cs.ScanResultReport {
		CustomerGUID: cusGUID,
		ImgTag: imagetag,
		ImgHash: "",
		WLID: wlid,
		Timestamp: timestamp,
		Layers: *layersList,
	}

	payload, err := json.Marshal(final_report)
	if err != nil {
		log.Printf("fail convert to json")
		return err
	}
	resp, err := http.Post(eventRecieverURL + "/k8s/containerScan", "application/json", bytes.NewReader(payload))
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

func GetScanResult(imagetag string) (*cs.LayersList, error) {

	ociImage, err := ociClient.Image(imagetag)
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
		return nil, err
	}
	
	scanresultlayer, err := GetClairScanResultsByLayer(manifest, packageManager, imagetag)
	if err != nil {
		log.Printf("GetClairScanResultsByLayer failed with err %v", err)
		return nil, err
	}

	return scanresultlayer, nil
}

func ProcessScanRequest(imagetag string, wlid string) (*cs.LayersList, error) {
	result, err := GetScanResult(imagetag)
	if err != nil {
		return nil, err
	}
	postScanResultsToEventReciever(imagetag, wlid, result)
	return result, nil
}
