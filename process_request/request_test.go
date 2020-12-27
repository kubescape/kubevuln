package process_request

import (
	"ca-vuln-scan/catypes"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func getTestNginxSigningProfile() (*catypes.SigningProfile, error) {
	file, err := ioutil.ReadFile("sp_nginx.json")
	if err != nil {
		return nil, err
	}
	sp := catypes.SigningProfile{}
	err = json.Unmarshal([]byte(file), &sp)
	if err != nil {
		return nil, err
	}
	return &sp, nil
}

func TestFullTestCycle(t *testing.T) {
	requestID := make([]byte, 16)
	sp, err := getTestNginxSigningProfile()
	if err != nil {
		t.Fatalf("Cannot read nginx signing profile: %s", err)
		return
	}
	scanResult, err := ProcessScanRequest(requestID, "wlid://datacenter-benlt/project-test/dockerized-nginx", sp)
	if err != nil {
		t.Fatalf("Failed scanning: %s", err)
		return
	}
	t.Logf("Passed scanning of %s", scanResult.ImageTag)
	for _, feature := range *scanResult.Features {
		t.Logf("Package %s", feature.Name)
		for _, vulnerability := range feature.Vulnerabilities {
			t.Logf("\t%s - %s", vulnerability.Name, vulnerability.Relevance)
		}
	}

}
