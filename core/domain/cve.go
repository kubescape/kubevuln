package domain

type CVE struct {
	ImageID            string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
	Content            []byte
}
