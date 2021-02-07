package process_request

import (
	"fmt"
	"strings"
)

type PackageHandler interface {
	initPackageHandler(image *OciImage) error
	readFileListForPackage(packageName string) (*[]string, error)
}

type dpkgPackageHandler struct {
	dpkgDirectoryList *OciImageFsList
	image             *OciImage
}

type apkPackageHandler struct {
	packageFileMap *map[string][]string
	image          *OciImage
}

func readFileListForPackageDpkg(packageName string, image *OciImage) (*[]string, error) {
	var packageFileList = []string{"/var/lib/dpkg/info/%s.list", "/var/lib/dpkg/info/%s:amd64.list"}
	for _, name := range packageFileList {
		listFilePath := fmt.Sprintf(name, packageName)
		fileContent, err := image.GetFile(listFilePath)
		if err == nil {
			fileList := strings.Split(string(*fileContent), "\n")
			return &fileList, nil
		}
	}
	return nil, fmt.Errorf("Could not find package %s", packageName)
}

func readFileListForPackageApk(packageName string, image *OciImage) (*[]string, error) {
	return nil, fmt.Errorf("unsupported Apk")
}

func readFileListForPackageYum(packageName string, image *OciImage) (*[]string, error) {
	return nil, fmt.Errorf("unsupported Yum")
}

func readFileListForPackage(packageName string, packageManagerType string, image *OciImage) (*[]string, error) {
	var err error
	var fileList *[]string
	switch packageManagerType {
	case "dpkg":
		fileList, err = readFileListForPackageDpkg(packageName, image)
	case "apk":
		fileList, err = readFileListForPackageApk(packageName, image)
	case "yum":
		fileList, err = readFileListForPackageYum(packageName, image)
	default:
		fileList = nil
		err = fmt.Errorf("Unsupported packager type %s", packageManagerType)
	}
	return fileList, err
}

func identifyPackageManager(image *OciImage) (string, error) {
	fileList, err := image.ListDirectoryFile("/var/lib/dpkg/info", true, false)
	if err == nil && len(*fileList) > 0 {
		return "dpkg", nil
	}
	fileList, err = image.ListDirectoryFile("/lib/apk", false, false)
	if err == nil && len(*fileList) > 0 {
		return "apk", nil
	}
	fileList, err = image.ListDirectoryFile("/lib/rpm", false, false)
	if err == nil && len(*fileList) > 0 {
		return "yum", nil
	}
	return "", fmt.Errorf("Cannot identify package manager in image %s", image.ImageNameRef)
}

func CreatePackageHandler(image *OciImage) (PackageHandler, error) {
	var err error
	var packageHandler PackageHandler

	packageManagerType, err := identifyPackageManager(image)
	if err != nil {
		return nil, err
	}

	switch packageManagerType {
	case "dpkg":
		packageHandler = &dpkgPackageHandler{}
		err = packageHandler.initPackageHandler(image)
	case "apk":
		packageHandler = &apkPackageHandler{}
		err = packageHandler.initPackageHandler(image)
	case "yum":
		packageHandler = &apkPackageHandler{}
		err = packageHandler.initPackageHandler(image)
	default:
		err = fmt.Errorf("Unsupported packager type %s", packageManagerType)
	}
	return packageHandler, err
}

func (ph *dpkgPackageHandler) initPackageHandler(image *OciImage) error {
	ph.image = image
	// Pre-read the list of files in /var/lib/dpkg/info
	fileContent, err := image.ListDirectoryFile("/var/lib/dpkg/info", false, false)
	if err == nil {
		ph.dpkgDirectoryList = fileContent
		return nil
	}
	return fmt.Errorf("Error initialization in dpkg handler %s", err)
}

func (ph *dpkgPackageHandler) readFileListForPackage(packageName string) (*[]string, error) {
	// Check package name
	for _, fsEntry := range *ph.dpkgDirectoryList {
		var packageFileList = []string{fmt.Sprintf("var/lib/dpkg/info/%s.list", packageName), fmt.Sprintf("var/lib/dpkg/info/%s:amd64.list", packageName)}
		for _, packageFileName := range packageFileList {
			//log.Printf("%s ?= %s", packageFileName, fsEntry.path)
			//if strings.HasPrefix(fsEntry.Path, packageFileName) && strings.HasSuffix(fsEntry.Path, ".list") {
			if fsEntry.Path == packageFileName {
				// gotcha!
				fileContent, err := ph.image.GetFile("/" + fsEntry.Path)
				if err != nil {
					return nil, err
				} else {
					fileList := strings.Split(string(*fileContent), "\n")
					return &fileList, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("Not found package %s", packageName)
}

func (ph *apkPackageHandler) initPackageHandler(image *OciImage) error {
	ph.image = image
	apkInstallDb, err := ph.image.GetFile("/lib/apk/db/installed")
	if err != nil {
		return err
	}
	ph.packageFileMap, err = apkInstallDbParser(apkInstallDb)
	return err
}

func (ph *apkPackageHandler) readFileListForPackage(packageName string) (*[]string, error) {
	// Check package name
	if fileList, hasKey := (*ph.packageFileMap)[packageName]; hasKey {
		return &fileList, nil
	}
	return nil, fmt.Errorf("package not found")

	return nil, fmt.Errorf("Not found package %s", packageName)
}
