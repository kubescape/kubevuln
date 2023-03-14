package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
)

type CVEExceptions []armotypes.VulnerabilityExceptionPolicy

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	ImageID            string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            *softwarecomposition.GrypeDocument
}
