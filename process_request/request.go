package process_request

import (
	"ca-vuln-scan/catypes"
	"fmt"
	"log"

	"github.com/docker/distribution/reference"
)

var ociClient OcimageClient

func init() {
	ociClient.endpoint = "http://localhost:8080"
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

func ProcessScanRequest(requestID []byte, containerImageRefernce string, signatureProfile *catypes.SigningProfile) error {
	if signatureProfile != nil {
		containerImageRefernce = signatureProfile.Attributes.DockerImageTag
	}
	_, err := reference.Parse(containerImageRefernce)
	if err != nil {
		return err
	}

	ociImage, err := ociClient.Image(containerImageRefernce)
	if err != nil {
		log.Printf("Not able to get image %s", err)
		return err
	}

	manifest, err := ociImage.GetManifest()
	if err != nil {
		log.Printf("Not able to get manifest %s", err)
		return err
	}

	featuresWithVulnerabilities, err := CreateClairScanResults(manifest)
	if err != nil {
		log.Printf("Not able to read scan results from Clair %s", err)
		return err
	}

	//fileListPerFeature := make(map[string]*[]string)
	for _, feature := range *featuresWithVulnerabilities {
		fileList, err := readFileListForPackage(feature.Name, "dpkg", ociImage)
		if err != nil {
			log.Printf("Not found file list for package %s", feature.Name)
			for i := range feature.Vulnerabilities {
				feature.Vulnerabilities[i].Relevance = "Unknown"
			}
		} else {
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

	fmt.Printf("signature profile: %s and %s", signatureProfile.Name, manifest.Config.Digest)
	// get clair scan

	return nil
}
