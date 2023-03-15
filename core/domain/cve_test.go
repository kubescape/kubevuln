package domain

import (
	"testing"

	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
)

func TestNewCVEManifest(t *testing.T) {
	NewCVEManifest("imageID", "SBOMCreatorVersion", "CVEScannerVersion", "CVEDBVersion", []cs.CommonContainerVulnerabilityResult{})
}
