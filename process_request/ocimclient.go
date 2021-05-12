package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	wssc "github.com/armosec/capacketsgo/apis"
	"github.com/golang/glog"
)

type OcimageClient struct {
	endpoint string
}

type OciImage struct {
	ImageNameRef string
	ImageID      []byte
	Client       *OcimageClient
}

type OciImageManifestConfig struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
}

type OciImageManifestRequestOptions struct {
	AllowRedirects bool              `json:"allow_redirects"`
	Stream         bool              `json:"stream"`
	Verify         bool              `json:"verify"`
	Headers        map[string]string `json:"headers"`
}

type OciImageManifestLayer struct {
	Digest         string                         `json:"digest"`
	DownloadPath   string                         `json:"dlPath"`
	MediaType      string                         `json:"mediaType"`
	Size           int                            `json:"size"`
	RequestOptions OciImageManifestRequestOptions `json:"request_options"`
}

type OciImageManifest struct {
	Config OciImageManifestConfig  `json:"config"`
	Layers []OciImageManifestLayer `json:"layers"`
}

//{"isSymbolicLink":false,"layer":"sha256:86b54f4b6a4ebee33338eb7c182a9a3d51a69cce1eb9af95a992f4da8eabe3be","link":"","name":"var/lib/dpkg/info/libdbus-1-3.list","path":"var/lib/dpkg/info/libdbus-1-3.list","permissions":"0o100644"},
type OciImageFsEntry struct {
	IsSymbolicLink bool   `json:"isSymbolicLink"`
	Layer          string `json:"layer"`
	Link           string `json:"link"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	Permissions    string `json:"permissions"`
}

type OciImageFsList []OciImageFsEntry

func CreateOciClient(endpoint string) (*OcimageClient, error) {
	return &OcimageClient{
		endpoint: endpoint,
	}, nil
}

func (OciClient *OcimageClient) Image(scanCmd *wssc.WebsocketScanCommand) (*OciImage, error) {
	var postStr []byte
	if scanCmd.Credentials != nil {
		glog.Infof("current image %v current creds : \n%v\nscancmd: %v\n\n", scanCmd.ImageTag, *scanCmd.Credentials, scanCmd)
	}
	if scanCmd.Credentials == nil || scanCmd.Credentials.Username == "" || scanCmd.Credentials.Password == "" {
		glog.Infof("no credentials scenario")
		postStr = []byte(fmt.Sprintf(`{"image": "%s"}`, scanCmd.ImageTag))
	} else {
		glog.Infof("credentials scenario")
		postStr = []byte(fmt.Sprintf(`{"image": "%s","username": %s,"password": %s}`, scanCmd.ImageTag, scanCmd.Credentials.Username, scanCmd.Credentials.Password))
	}

	url := fmt.Sprintf("%s/v1/images/id", OciClient.endpoint)
	glog.Infof("Image() creating request to %v", url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(postStr))
	if err != nil {
		glog.Errorf("Image(): failed to create request to url: %v\n%v", url, err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	httpclient := &http.Client{}
	resp, err := httpclient.Do(req)
	if err != nil {
		glog.Errorf("Image(): failed to request to url: %v\n%v", url, err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		imageID, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return &OciImage{
			ImageNameRef: scanCmd.ImageTag,
			ImageID:      imageID,
			Client:       OciClient,
		}, nil
	}
	return nil, fmt.Errorf("HTTP failed %d", resp.StatusCode)
}

func (image *OciImage) GetManifest() (*OciImageManifest, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/images/id/%s/manifest", image.Client.endpoint, image.ImageID), nil)
	req.Header.Set("Content-Type", "application/json")

	httpclient := &http.Client{}
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		jsonRaw, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		//log.Print(string(jsonRaw))
		manifest := OciImageManifest{}
		if err := json.Unmarshal(jsonRaw, &manifest); err != nil {
			return nil, err
		}

		return &manifest, nil
	}

	return nil, fmt.Errorf("HTTP failed %d", resp.StatusCode)
}

func (image *OciImage) GetFile(fileName string) (*[]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/images/id/%s/files%s", image.Client.endpoint, image.ImageID, fileName), nil)

	httpclient := &http.Client{
		Timeout: 600 * time.Second,
	}
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		fileRaw, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return &fileRaw, nil
	}

	return nil, fmt.Errorf("HTTP failed %d", resp.StatusCode)
}

func (image *OciImage) ListDirectoryFile(path string, no_dir bool, recursive bool) (*OciImageFsList, error) {
	requestURL := fmt.Sprintf("%s/v1/images/id/%s/list?from=0", image.Client.endpoint, image.ImageID)
	if no_dir {
		requestURL += "&no_dir=true"
	} else {
		requestURL += "&no_dir=false"
	}
	if recursive {
		requestURL += "&recursive=true"
	} else {
		requestURL += "&recursive=false"
	}
	requestURL += "&dir="
	if path[0] == '/' {
		requestURL += path[1:]
	} else {
		requestURL += path
	}

	// http://127.0.0.1:5000/v1/images/id/f6695b2d24dd2e1da0a79fa72459e33505da79939c13ce50e90675c32988ab64/
	//list?from=0&no_dir=true&recursive=true&dir=var/lib
	// http://127.0.0.1:5000/v1/images/id/f6695b2d24dd2e1da0a79fa72459e33505da79939c13ce50e90675c32988ab64/list?from=0&no_dir=true&recursive=true&dir=var/lib
	req, err := http.NewRequest("GET", requestURL, nil)
	//
	httpclient := &http.Client{
		Timeout: 600 * time.Second,
	}
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		jsonRaw, err := ioutil.ReadAll(resp.Body)
		//log.Printf("json\n%s", jsonRaw)
		if err != nil {
			return nil, err
		}
		var fileList OciImageFsList
		err = json.Unmarshal(jsonRaw, &fileList)
		if err != nil {
			return nil, err
		}
		return &fileList, nil
	}

	return nil, fmt.Errorf("HTTP failed %d", resp.StatusCode)
}
