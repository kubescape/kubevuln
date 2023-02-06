package domain

type SBOM struct {
	ImageID            string
	SBOMCreatorVersion string
	Content            []byte
}

type RegistryCredentials struct {
	Authority string
	Username  string
	Password  string
	Token     string
}

type RegistryOptions struct {
	InsecureSkipTLSVerify bool
	InsecureUseHTTP       bool
	Credentials           []RegistryCredentials
	Platform              string
}
