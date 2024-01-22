package secretdetector

// SecretDetectionResult is a struct for holding the result of a secret detection
type SecretDetectionResult struct {
	Type   string
	Value  string
	Line   int
	Index  int
	Length int
}

type FileDetectionConfig struct {
	SkipBinaryFiles bool
	SizeThreshold   int64
}

type FileDetectionResult struct {
	Path    string
	Err     error
	Results []SecretDetectionResult
}
