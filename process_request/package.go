package process_request

import (
	"fmt"
	"strings"
)

func readFileListForPackageDpkg(packageName string, image *OciImage) (*[]string, error) {
	listFilePath := fmt.Sprintf("/var/lib/dpkg/info/%s.list", packageName)
	fileContent, err := image.GetFile(listFilePath)
	if err != nil {
		return nil, err
	}
	fileList := strings.Split(string(*fileContent), "\n")
	return &fileList, nil
}

func readFileListForPackageApk(packageName string, image *OciImage) (*[]string, error) {
	return nil, fmt.Errorf("unsupported Apk")
}

func readFileListForPackage(packageName string, packageManagerType string, image *OciImage) (*[]string, error) {
	var err error
	var fileList *[]string
	switch packageManagerType {
	case "dpkg":
		fileList, err = readFileListForPackageDpkg(packageName, image)
	case "apk":
		fileList, err = readFileListForPackageApk(packageName, image)
	default:
		fileList = nil
		err = fmt.Errorf("Unsupported packager type %s", packageManagerType)
	}
	return fileList, err
}
