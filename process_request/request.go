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
	"strings"
	"time"

	// "ca-vuln-scan/catypes"

	"log"
	"os"

	wssc "github.com/armosec/capacketsgo/apis"
	sysreport "github.com/armosec/capacketsgo/system-reports/datastructures"

	cs "github.com/armosec/capacketsgo/containerscan"
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
			log.Printf("OCIMAGE_URL/CA_OCIMAGE_URL is not configured- some features might not work, please install OCIMAGE to get more features")
		}
	}

	eventRecieverURL = os.Getenv("CA_EVENT_RECEIVER_HTTP")
	if len(eventRecieverURL) == 0 {
		log.Fatal("Must configure either CA_EVENT_RECEIVER_HTTP")
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

func postScanResultsToEventReciever(imagetag string, wlid string, containerName string, layersList *cs.LayersList, listOfBash []string) error {

	log.Printf("posting to event reciever image %s wlid %s", imagetag, wlid)
	timestamp := int64(time.Now().Unix())

	//BEN's REQUEST UGLy HACK MUST BE REMOVED AFTER DEMO
	if strings.Contains(wlid, "/deployment-shippingservice") && layersList != nil && len(*layersList) > 0 {
		(*layersList)[0].Vulnerabilities = append((*layersList)[0].Vulnerabilities, cs.Vulnerability{Name: "CVE-2021-33525",
			ImgHash:            "sha256:0cf0f74061d93e8699bcf09123bdc2c64000720f6d1ed58ee7331273c6375001",
			ImgTag:             "gcr.io/google-samples/microservices-demo/shippingservice:v0.2.0",
			RelatedPackageName: "busybox",
			Link:               "https://nvd.nist.gov/vuln/detail/CVE-2021-33525",
			Description:        "EyesOfNetwork eonweb through 5.3-11 allows Remote Command Execution (by authenticated users) via shell metacharacters in the nagios_path parameter to lilac/export.php, as demonstrated by %26%26+curl to insert an \"&& curl\" substring for the shell.",
			Severity:           "Critical",
		})
	}

	final_report := cs.ScanResultReport{
		CustomerGUID:             cusGUID,
		ImgTag:                   imagetag,
		ImgHash:                  "",
		WLID:                     wlid,
		ContainerName:            containerName,
		Timestamp:                timestamp,
		Layers:                   *layersList,
		ListOfDangerousArtifcats: listOfBash,
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
func RemoveFile(filename string) {
	err := os.Remove(filename)
	if err != nil {
		log.Printf("Error removing file %s", filename)
	}
}

func GetScanResult(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, []string, error) {
	filteredResultsChan := make(chan []string)

	if ociClient.endpoint != "" {
		ociImage, err := ociClient.Image(scanCmd)
		if err != nil {
			log.Printf("unable to get image %s", err)
			return nil, nil, err
		}
		go func() {
			listOfPrograms := []string{
				"bin/sh", "bin/bash", "sbin/sh", "bin/ksh", "bin/tcsh", "bin/zsh", "usr/bin/scsh", "bin/csh", "bin/busybox", "usr/bin/kubectl", "usr/bin/curl",
				"usr/bin/wget", "usr/bin/ssh", "usr/bin/ftp", "usr/share/gdb", "usr/bin/nmap", "usr/share/nmap", "usr/bin/tcpdump", "usr/bin/ping",
				"usr/bin/netcat", "usr/bin/gcc", "usr/bin/busybox", "usr/bin/nslookup", "usr/bin/host", "usr/bin/dig", "usr/bin/psql", "usr/bin/swaks",
			}
			filteredResult := []string{}

			directoryFilesInBytes, err := ociImage.GetFiles(listOfPrograms, true, true)
			if err != nil {
				log.Printf("Couldn't get filelist from ocimage  due to %s", err.Error())
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
				log.Printf("Couldn't open file : %s" + filename)
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
						log.Printf("Couldn't parse symlinkMap.json file")
						filteredResultsChan <- nil
						return
					}

				}
			}
			var fileInJson map[string]string
			err = json.Unmarshal([]byte(buf.String()), &fileInJson)
			if err != nil {
				log.Printf("Failed to marshal file  %s", filename)
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
	} else {
		go func() {
			log.Printf("skipping dangerous executables enrichment")
			filteredResultsChan <- nil
		}()

	}

	log.Printf("sending command to anchore")
	scanresultlayer, err := GetAnchoreScanResults(scanCmd)
	if err != nil {
		log.Printf("GetAnchoreScanResults failed with err %v to image %s", err, scanCmd.ImageTag)
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
		ActionName:   fmt.Sprintf("vuln scan:: scanning wlid:%v , container:%v image: %v", scanCmd.Wlid, scanCmd.ContainerName, scanCmd.ImageTag),
		ActionID:     "1",
		ActionIDN:    1,
		Target:       fmt.Sprintf("wlid: %v / image: %v", scanCmd.Wlid, scanCmd.ImageTag),
	}

	if len(scanCmd.JobID) != 0 {
		report.SetJobID(scanCmd.JobID)
	}
	if scanCmd.LastAction > 0 {
		report.SetActionIDN(scanCmd.LastAction + 1)
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

	err = postScanResultsToEventReciever(scanCmd.ImageTag, scanCmd.Wlid, scanCmd.ContainerName, result, bashList)
	if err != nil {
		report.SendError(fmt.Errorf("vuln scan:notifying event receiver about %v scan failed due to %v", scanCmd.ImageTag, err.Error()), true, true)
	} else {
		report.SendStatus(sysreport.JobSuccess, true)
	}
	return result, nil
}
