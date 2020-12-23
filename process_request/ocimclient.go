package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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

func CreateOciClient(endpoint string) (*OcimageClient, error) {
	return &OcimageClient{
		endpoint: endpoint,
	}, nil
}

func (OciClient *OcimageClient) Image(containerImageRef string) (*OciImage, error) {
	postStr := []byte(fmt.Sprintf(`{"image": "%s"}`, containerImageRef))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/images/id", OciClient.endpoint), bytes.NewBuffer(postStr))
	req.Header.Set("Content-Type", "application/json")

	httpclient := &http.Client{}
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		imageID, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return &OciImage{
			ImageNameRef: containerImageRef,
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
