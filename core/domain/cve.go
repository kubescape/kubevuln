package domain

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	ImageID            string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            []byte
}
