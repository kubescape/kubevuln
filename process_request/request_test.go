package process_request

import (
	"testing"
)

func TestFullTestCycleDpkg(t *testing.T) {
	imagetag := "nginx"
	scanResult, err := ProcessScanRequest(imagetag, "wlid://datacenter-benlt/project-test/dockerized-nginx")
	if err != nil {
		t.Fatalf("Failed scanning: %s", err)
		return
	}
}

func TestFullTestCycleDpkgWithS3(t *testing.T) {

	imagetag := "nginx"
	_, err := ProcessScanRequest(imagetag, "wlid://datacenter-benlt/project-test/dockerized-nginx")
	if err != nil {
		t.Fatalf("Failed scanning: %s", err)
		return
	}
}

func TestFullTestCycleApk(t *testing.T) {
	requestID := make([]byte, 16)
	
	imagetag := "nginx"
	scanResult, err := ProcessScanRequest(imagetag, "wlid://cluster-hipster/namespace-hipster/deployment-adservice")
	if err != nil {
		t.Fatalf("Failed scanning: %s", err)
		return
	}

}
