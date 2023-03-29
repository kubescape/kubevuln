package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type CVEExceptions []armotypes.VulnerabilityExceptionPolicy

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	ID                 string
	Wlid               string
	SBOMCreatorName    string
	SBOMCreatorVersion string
	CVEScannerName     string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            *v1beta1.GrypeDocument
	Annotations        map[string]string
	Labels             map[string]string
}
