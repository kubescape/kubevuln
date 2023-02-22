package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
)

type CVEExceptions []armotypes.VulnerabilityExceptionPolicy

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	ImageID            string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            []cs.CommonContainerVulnerabilityResult
}

func NewCVEManifest(ImageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string, content []cs.CommonContainerVulnerabilityResult) *CVEManifest {
	return &CVEManifest{
		ImageID:            ImageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
		Content:            content,
	}
}
