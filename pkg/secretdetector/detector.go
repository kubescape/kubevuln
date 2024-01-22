package secretdetector

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	MAX_READ_SIZE = 8 * 1024 * 1024
)

// SearchDirectoryForSecrets searches a directory for files containing secrets
func SearchDirectoryForSecrets(directoryPath string, config *FileDetectionConfig) ([]FileDetectionResult, error) {
	var results []FileDetectionResult

	detectionRules, err := CompileDefaultRegexpRules()
	if err != nil {
		return nil, err
	}

	// Iterate over files in directory and its subdirectories
	err = filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		// Skip directories
		if info == nil ||
			info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode()&os.ModeNamedPipe != 0 ||
			info.Mode()&os.ModeSocket != 0 ||
			info.Mode()&os.ModeDevice != 0 ||
			info.Mode()&os.ModeCharDevice != 0 ||
			info.Mode()&os.ModeIrregular != 0 {
			return nil
		}

		if err != nil {
			return err
		}

		// fmt.Printf("Scanning file %s\n", path)

		// For each file, check if it contains a secret
		detectionResult, err := SearchFileForSecrets(path, config, detectionRules)
		if err != nil {
			results = append(results, FileDetectionResult{
				Path: path,
				Err:  err,
			})
		}

		// If it does, add it to the results
		if detectionResult != nil {
			results = append(results, *detectionResult)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Return the results
	return results, nil
}

func SearchFileForSecrets(filePath string, config *FileDetectionConfig, detectors []CompiledRegexpDetectionRule) (*FileDetectionResult, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if config != nil && config.SizeThreshold > 0 {
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}

		if fileInfo.Size() > config.SizeThreshold {
			return nil, nil
		}
	}

	result := &FileDetectionResult{
		Path: filePath,
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
