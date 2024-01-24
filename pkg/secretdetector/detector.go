package secretdetector

import (
	"fmt"
	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	syftFile "github.com/anchore/syft/syft/file"
)

const (
	MAX_READ_SIZE = 8 * 1024 * 1024
)

// SearchDirectoryForSecrets searches a directory for files containing secrets
func SearchDirectoryForSecrets(resolver syftFile.Resolver, config *FileDetectionConfig) ([]FileDetectionResult, error) {
	var results []FileDetectionResult

	detectionRules, err := CompileDefaultRegexpRules()
	if err != nil {
		return nil, err
	}

	// Iterate over files in directory and its subdirectories
	for location := range resolver.AllLocations() {
		resolvedLocations, err := resolver.FilesByPath(location.RealPath)
		if err != nil {
			continue
		}
		for _, resolvedLocation := range resolvedLocations {
			metadata, err := resolver.FileMetadataByLocation(resolvedLocation)
			if err != nil {
				continue
			}
			if metadata.Type != stereoscopeFile.TypeRegular {
				continue
			}

			fmt.Printf("Scanning file %s\n", resolvedLocation.Path())

			// For each file, check if it contains a secret
			detectionResult, err := SearchFileForSecrets(resolver, resolvedLocation, metadata, config, detectionRules)
			if err != nil {
				results = append(results, FileDetectionResult{
					Path: resolvedLocation.Path(),
					Err:  err,
				})
			}

			// If it does, add it to the results
			if detectionResult != nil {
				results = append(results, *detectionResult)
			}
		}
	}

	// Return the results
	return results, nil
}

func SearchFileForSecrets(resolver syftFile.Resolver, location syftFile.Location, fileInfo syftFile.Metadata, config *FileDetectionConfig, detectors []CompiledRegexpDetectionRule) (*FileDetectionResult, error) {

	if config != nil && config.SizeThreshold > 0 && fileInfo.Size() > config.SizeThreshold {
		return nil, nil
	}

	file, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := &FileDetectionResult{
		Path: location.Path(),
		Err:  nil,
	}

	// Read the file contents but no more than 8MB of data at a time
	for {
		data := make([]byte, MAX_READ_SIZE)
		count, err := file.Read(data)
		if err != nil {
			break
		}

		if config != nil && config.SkipBinaryFiles {
			for _, b := range data[:count] {
				if b == 0 {
					return nil, nil
				}
			}
		}

		for _, detector := range detectors {
			if foundIndices := detector.Regexp.FindAllIndex(data[:count], -1); foundIndices != nil {
				for _, foundIndex := range foundIndices {
					last_ndx := 0
					for i, foundSubIndex := range foundIndex {
						if i%2 == 0 {
							last_ndx = foundSubIndex
						} else {
							quaterLen := (foundSubIndex - last_ndx) / 8
							result.Results = append(result.Results, SecretDetectionResult{
								Type:   detector.Rule.Description,
								Value:  fmt.Sprintf("%s ... %s", data[last_ndx:last_ndx+quaterLen], data[foundSubIndex-quaterLen:foundSubIndex]),
								Line:   0,
								Index:  last_ndx,
								Length: foundSubIndex - last_ndx,
							})
						}
					}
				}
			}
		}

		if count < MAX_READ_SIZE {
			break
		}
	}

	if len(result.Results) == 0 {
		return nil, nil
	}
	return result, nil
}
