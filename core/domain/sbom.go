package domain

const (
	SBOMStatusTimedOut = "timed out"
)

// SBOM contains an SPDX SBOM in JSON format with some metadata
type SBOM struct {
	ImageID            string
	SBOMCreatorVersion string
	Status             string
	Content            []byte
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
	InsecureSkipTLSVerify bool
	InsecureUseHTTP       bool
	Credentials           []RegistryCredentials
	Platform              string
}
