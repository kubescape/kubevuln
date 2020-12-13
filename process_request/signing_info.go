package process_request

import "encoding/json"

// ModulesInformation holds data of specific module in signing profile
type ModulesInformation struct {
	FullPath                string `json:"fullPath"`
	Name                    string `json:"name"`
	Mandatory               int    `json:"mandatory"`
	Version                 string `json:"version,omitempty"`
	SignatureMismatchAction int    `json:"signatureMismatchAction,omitempty"`
	Type                    int    `json:"type,omitempty"`
}

// ExecutablesList holds the list of executables in this signing profile
type ExecutablesList struct {
	MainProcess                     string               `json:"mainProcess"`
	FullProcessCommandLine          string               `json:"fullProcessCommandLine,omitempty"`
	FullProcessEnvironmentVariables map[string]string    `json:"fullProcessEnvironmentVariables,omitempty"`
	ModulesInfo                     []ModulesInformation `json:"modulesInfo"`
	Filters                         FiltersSection       `json:"filter,omitempty"`
}

// FiltersSection holds the filter section of  ExecutablesList
type FiltersSection struct {
	IncludePaths      []string `json:"includePaths,omitempty"`
	IncludeExtensions []string `json:"includeExtensions,omitempty"`
}

// SigningProfile signingProfile configuration
type SigningProfile struct {
	Name            string                  `json:"name"`
	GUID            string                  `json:"guid"`
	Platform        int64                   `json:"platform"`
	Architecture    int64                   `json:"architecture"`
	CreationTime    string                  `json:"creation_time"`
	LastEditTime    string                  `json:"last_edit_time"`
	Attributes      SignigProfileAttributes `json:"attributes"`
	ExecutablesList []ExecutablesList       `json:"executablesList"` // Use structs from catypes
	FullPathMap     map[string]bool         `json:"-"`
}

// SignigProfileAttributes -
type SignigProfileAttributes struct {
	IsStockProfile    bool   `json:"isStockProfile,omitempty"`
	ContainerName     string `json:"containerName,omitempty"`
	DockerImageTag    string `json:"dockerImageTag,omitempty"`
	DockerImageSHA256 string `json:"dockerImageSHA256,omitempty"`
	GeneratedFor      string `json:"generatedFor,omitempty"`
	GeneratedFrom     string `json:"generatedFrom,omitempty"`
}

// ParseSigningProfileFromJSON: Create a SigningProfile object from JSON
func ParseSigningProfileFromJSON(json_string []byte) (SigningProfile, error) {
	var signingProfile SigningProfile
	err := json.Unmarshal(json_string, &signingProfile)
	if err != nil {
		return signingProfile, err
	}
	return signingProfile, nil
}
