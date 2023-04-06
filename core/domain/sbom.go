package domain

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	SBOMStatusIncomplete = "incomplete"
)

// SBOM contains an SPDX SBOM in JSON format with some metadata
type SBOM struct {
	ID                 string
	SBOMCreatorName    string
	SBOMCreatorVersion string
	Status             string
	Content            *v1beta1.Document
	Annotations        map[string]string
	Labels             map[string]string
}

// RegistryCredentials contains OCI registry credentials required for connection
// it is closely related to the Stereoscope image.RegistryCredentials struct
type RegistryCredentials struct {
	Authority string
	Username  string
	Password  string
	Token     string
}

// RegistryOptions contains OCI registry configuration parameters required for connection
// it is closely related to the Stereoscope image.RegistryOptions struct used by Grype
type RegistryOptions struct {
	Platform              string
	Credentials           []RegistryCredentials
	InsecureSkipTLSVerify bool
	InsecureUseHTTP       bool
}
