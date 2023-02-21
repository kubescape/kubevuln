package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	v2 "github.com/armosec/cluster-container-scanner-api/containerscan/v2"
)

type CVEExceptions []armotypes.VulnerabilityExceptionPolicy

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	ImageID            string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            *v2.ScanResultReport
}
