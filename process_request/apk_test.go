package process_request

import (
	"io/ioutil"
	"testing"
)

func TestApkDbParser(t *testing.T) {
	_, err := ioutil.ReadFile("apk.installed")
	if err != nil {
		t.Logf("Failed reading file apk.installed: %s", err)
		return
	}
	// apkPackageFileMap, err := apkInstallDbParser(&file)
	// if err != nil {
	// 	t.Logf("apkInstallDbParser failed: %s", err)
	// 	return
	// }
	// for packageKey := range *apkPackageFileMap {
	// 	t.Logf("Package %s", packageKey)
	// 	fileList := (*apkPackageFileMap)[packageKey]
	// 	for _, fileName := range fileList {
	// 		t.Logf("\t%s", fileName)
	// 	}
	// }
}
