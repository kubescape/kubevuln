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

func getTestFrontendSigningProfile() (*catypes.SigningProfile, error) {
	file, err := ioutil.ReadFile("sp_frontend.json")
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

func TestFullTestCycleDpkg(t *testing.T) {
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

func TestFullTestCycleApk(t *testing.T) {
	requestID := make([]byte, 16)
	sp, err := getTestFrontendSigningProfile()
	if err != nil {
		t.Fatalf("Cannot read adservice signing profile: %s", err)
		return
	}
	scanResult, err := ProcessScanRequest(requestID, "wlid://cluster-hipster/namespace-hipster/deployment-adservice", sp)
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
