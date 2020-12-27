package process_request

import "testing"

func TestDpkgGetFilesList(t *testing.T) {
	oci := OcimageClient{endpoint: "http://localhost:8080"}
	//image, err := oci.Image("debian:9")
	image, err := oci.Image("ubuntu:10.04")
	if err != nil {
		t.Fatalf("image failed: %s", err)
		return
	}
	t.Logf("ImageID: %s", image.ImageID)
	fileList, err := readFileListForPackage("apt", "dpkg", image)
	if err != nil {
		t.Fatalf("did not get file list: %s", err)
		return
	} else {
		for _, fileName := range *fileList {
			t.Log(fileName)
		}
	}
}

func TestHandlerDpkgGetFilesList(t *testing.T) {
	oci := OcimageClient{endpoint: "http://localhost:8080"}
	//image, err := oci.Image("debian:9")
	image, err := oci.Image("ubuntu:10.04")
	if err != nil {
		t.Fatalf("image failed: %s", err)
		return
	}
	packageManager, err := CreatePackageHandler("dpkg", image)
	if err != nil {
		t.Fatalf("package manager failed: %s", err)
		return
	}
	t.Logf("ImageID: %s", image.ImageID)
	fileList, err := packageManager.readFileListForPackage("apt")
	if err != nil {
		t.Fatalf("did not get file list: %s", err)
		return
	} else {
		for _, fileName := range *fileList {
			t.Log(fileName)
		}
	}
}
