package process_request

import (
	"fmt"
	"testing"
)

func TestClairScanResults(t *testing.T) {
	manifest, err := getContainerImageManifest("debian:9")
	if err != nil {
		t.Errorf("get manifest failed: %s", err)
		return
	}
	featuresWithVulnerabilities, ferr := CreateClairScanResults(manifest)
	if ferr != nil {
		t.Errorf("scan failed: %s", ferr)
		return
	}

	for _, feature := range *featuresWithVulnerabilities {
		fmt.Printf("=== %s %s ===\n", feature.Name, feature.Version)
		for _, vulnerability := range feature.Vulnerabilities {
			fmt.Printf("    %s\n", vulnerability.Name)
		}
	}
}
