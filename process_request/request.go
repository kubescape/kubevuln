package process_request

import (
	"bytes"
	"ca-vuln-scan/catypes"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/docker/distribution/reference"
)

type ScanResult struct {
	ImageTag   string          `json:"imageTag"`
	ImageHash  string          `json:"imageHash"`
	WorkloadId string          `json:"wlid"`
	Features   *[]ClairFeature `json:"features"`
}

var ociClient OcimageClient
var scanDeliveryBucket string

func init() {
	ociClient.endpoint = os.Getenv("OCIMAGE_URL")
	if len(ociClient.endpoint) == 0 {
		log.Fatal("Must configure OCIMAGE_URL")
	}
	scanDeliveryBucket = os.Getenv("S3_BUCKET")
	if len(scanDeliveryBucket) == 0 {
		log.Fatal("Must configure S3_BUCKET")
	}
	if len(os.Getenv("AWS_ACCESS_KEY_ID")) == 0 {
		log.Fatal("Must configure AWS_ACCESS_KEY_ID")
	}
	if len(os.Getenv("AWS_SECRET_ACCESS_KEY")) == 0 {
		log.Fatal("Must configure AWS_SECRET_ACCESS_KEY")
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

func postScanResults(customerGuid string, solutionGuid string, result *ScanResult) {
	key := customerGuid + "/" + solutionGuid + "/" + "result.json"
	log.Printf("Starting uploading %s to bucket %s", key, scanDeliveryBucket)
	jsonRaw, err := json.Marshal(result)
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		log.Printf("Error configuring S3 client (%s - %s)", key, result.WorkloadId)
	}
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(scanDeliveryBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(jsonRaw),
	})
	if err != nil {
		log.Printf("Error posting scan results to S3 - error: %s (%s - %s)", err, key, result.WorkloadId)
	} else {
		log.Printf("Uploaded %s to bucket %s", key, scanDeliveryBucket)
	}
}

func ProcessScanRequest(requestID []byte, workloadId string, signatureProfile *catypes.SigningProfile) (*ScanResult, error) {
	containerImageRefernce := signatureProfile.Attributes.DockerImageTag

	_, err := reference.Parse(containerImageRefernce)
	if err != nil {
		return nil, err
	}

	ociImage, err := ociClient.Image(containerImageRefernce)
	if err != nil {
		log.Printf("Not able to get image %s", err)
		return nil, err
	}

	manifest, err := ociImage.GetManifest()
	if err != nil {
		log.Printf("Not able to get manifest %s", err)
		return nil, err
	}

	featuresWithVulnerabilities, err := CreateClairScanResults(manifest)
	if err != nil {
		log.Printf("Not able to read scan results from Clair %s", err)
		return nil, err
	}

	packageManager, err := CreatePackageHandler(ociImage)
	if err != nil {
		log.Printf("Package handler cannot be initialized %s", err)
		return nil, err
	}

	for _, feature := range *featuresWithVulnerabilities {
		if len(feature.Vulnerabilities) > 0 {
			fileList, err := packageManager.readFileListForPackage(feature.Name)
			if err != nil {
				log.Printf("Not found file list for package %s", feature.Name)
				for i := range feature.Vulnerabilities {
					feature.Vulnerabilities[i].Relevance = "Unknown"
				}
			} else {
				log.Printf("Found file list for package %s", feature.Name)
				relevance := "Irrelevant"
				for _, fileName := range *fileList {
					for _, executable := range signatureProfile.ExecutableList {
						for _, module := range executable.ModulesInfo {
							if fileName == module.FullPath {
								relevance = "Relevant"
								break
							}
						}
						if relevance == "Relevant" {
							break
						}
					}
					if relevance == "Relevant" {
						break
					}
				}
				for i := range feature.Vulnerabilities {
					feature.Vulnerabilities[i].Relevance = relevance
				}
			}
		}
	}

	var result *ScanResult

	result = &ScanResult{
		ImageTag:   signatureProfile.Attributes.DockerImageTag,
		ImageHash:  signatureProfile.Attributes.DockerImageSHA256,
		WorkloadId: workloadId,
		Features:   featuresWithVulnerabilities,
	}

	return result, nil
}

func ProcessScanRequestWithS3Upload(requestID []byte, customerGuid string, solutionGuid string, workloadId string, signatureProfile *catypes.SigningProfile) (*ScanResult, error) {
	result, err := ProcessScanRequest(requestID, workloadId, signatureProfile)
	if err != nil {
		return nil, err
	}
	postScanResults(customerGuid, solutionGuid, result)
	return result, nil
}
