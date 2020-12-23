package process_request

import (
	"fmt"

	"github.com/docker/distribution/reference"
)

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

func ProcessScanRequest(requestID []byte, containerImageRefernce string, signatureProfileJson string) error {

	_, err := reference.Parse(containerImageRefernce)
	if err != nil {
		return err
	}

	signatureProfile, err := ParseSigningProfileFromJSON([]byte(signatureProfileJson))
	if err != nil {
		return err
	}

	manifest, err := getContainerImageManifest(containerImageRefernce)
	if err != nil {
		return err
	}

	fmt.Printf("signature profile: %s and %s", signatureProfile.Name, manifest.Config.Digest)
	// get clair scan

	return nil
}
