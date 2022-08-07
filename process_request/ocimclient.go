package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
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

func (OciClient *OcimageClient) Image(scanCmd *wssc.WebsocketScanCommand) (*OciImage, error) {

	values := map[string]string{"image": scanCmd.ImageTag}

	if scanCmd.Credentials != nil && len(scanCmd.Credentials.Username) != 0 && len(scanCmd.Credentials.Password) != 0 {
		glog.Infof("credentials scenario")
		values["username"] = scanCmd.Credentials.Username
		values["password"] = scanCmd.Credentials.Password
	}
	payload, err := json.Marshal(values)
	if err != nil {
		glog.Errorf("unable to marshal ocimage payload")
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/images/id", OciClient.endpoint)
	glog.Infof("Image() creating request to %v", url)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
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
	return nil, fmt.Errorf("HTTP failed %d due to: %v", resp.StatusCode, resp.Status)
}

func (image *OciImage) GetFiles(fileList []string, followSymLink bool, checkExist bool) (*[]byte, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/images/id/%s/files", image.Client.endpoint, image.ImageID), nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	for _, file := range fileList {
		q.Add("file", file)
	}
	q.Add("followSymLink", strconv.FormatBool(followSymLink))
	q.Add("checkExist", strconv.FormatBool(checkExist))

	req.URL.RawQuery = q.Encode()
	req.Header.Add("Accept-Encoding", "gzip")
	httpclient := &http.Client{
		Timeout: (60 * time.Duration(len(fileList))) * time.Second,
	}

	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return &bodyBytes, nil
	}

	return nil, fmt.Errorf("HTTP failed %d", resp.StatusCode)
}
