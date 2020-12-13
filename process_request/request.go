package process_request

import (
	"fmt"

	"github.com/docker/distribution/reference"
)

func ProcessScanRequest(requestID []byte, containerImageRefernce string, signatureProfileJson string) error {

	_, err := reference.Parse(containerImageRefernce)
	if err != nil {
		return err
	}

	signatureProfile, err := ParseSigningProfileFromJSON([]byte(signatureProfileJson))
	if err != nil {
		return err
	}

	fmt.Printf("signature profile: %s", signatureProfile.Name)
	// get clair scan

	return nil
}
