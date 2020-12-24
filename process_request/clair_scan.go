package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var clairUrl string

func init() {
	clairUrl = "http://35.246.251.137:6060"
}

type ClairLayer struct {
	Name             string
	Path             string
	Headers          map[string]string
	ParentName       string
	Format           string
	NamespaceName    string
	IndexedByVersion int
	Features         []ClairFeature
}

type EnclosedClairLayer struct {
	Layer ClairLayer
}

type ClairVulnerabilty struct {
	Name         string
	NamepaceName string
	Description  string
	Severity     string
	Link         string
	Relevance    string `json:"group,omitempty"`
}

type EnclosedClairVulnerabilities struct {
	Vulnerabilities []ClairVulnerabilty
	NextPage        string
}

type ClairFeature struct {
	Name            string
	NamespaceName   string
	Version         string
	Vulnerabilities []ClairVulnerabilty
}

func getLayerNameFromDigest(digest string) string {
	cp := strings.Index(digest, ":")
	if 0 < cp {
		return digest[cp+1:]
	}
	return digest
}

func createClairLayersFromOciManifest(manifest *OciImageManifest) *[]ClairLayer {
	uniqueLayerCount := 0
	for i, _ := range manifest.Layers {
		if 0 < i {
			if manifest.Layers[i-1].Digest == manifest.Layers[i].Digest {
				continue
			}
		}
		uniqueLayerCount++
	}
	cLayers := make([]ClairLayer, uniqueLayerCount)
	j := 0
	for i, ociLayer := range manifest.Layers {
		if 0 < i {
			if manifest.Layers[i-1].Digest == manifest.Layers[i].Digest {
				continue
			}
		}
		cLayers[j].Name = getLayerNameFromDigest(ociLayer.Digest)
		log.Printf("created layer %s -> %s", ociLayer.Digest, cLayers[j].Name)
		cLayers[j].Path = ociLayer.DownloadPath
		cLayers[j].Headers = ociLayer.RequestOptions.Headers
		cLayers[j].Format = "Docker"
		if 0 < j {
			cLayers[j].ParentName = getLayerNameFromDigest(manifest.Layers[j-1].Digest)
		}
		j++
	}
	return &cLayers
}

func postClairLayerV1(layer *ClairLayer) error {
	payload, err := json.Marshal(EnclosedClairLayer{Layer: *layer})
	if err != nil {
		return err
	}
	resp, err := http.Post(clairUrl+"/v1/layers", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 299 < resp.StatusCode {
		return fmt.Errorf("clair post layer failed with %d", resp.StatusCode)
	}
	log.Printf("Posted layer %s to Clair with code %d", layer.Name, resp.StatusCode)
	return nil
}

func getClairLayerV1(layer *ClairLayer) error {
	resp, err := http.Get(clairUrl + "/v1/layers/" + layer.Name + "?features&vulnerabilities")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 299 < resp.StatusCode {
		return fmt.Errorf("clair get layer failed with %d", resp.StatusCode)
	}
	//log.Printf("Got layer %s to Clair with code %d", layer.Name, resp.StatusCode)
	jsonRaw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var parsingLayer EnclosedClairLayer
	err = json.Unmarshal(jsonRaw, &parsingLayer)
	if err == nil {
		log.Printf("Got back layer %s with %d features", parsingLayer.Layer.Name, len(parsingLayer.Layer.Features))
		*layer = parsingLayer.Layer
	}
	return err
}

func CreateClairScanResults(manifest *OciImageManifest) (*[]ClairFeature, error) {
	var clairLayers *[]ClairLayer
	var err error

	clairLayers = createClairLayersFromOciManifest(manifest)
	log.Printf("Posting layers for %s to Clair", manifest.Config.Digest)
	for _, cLayer := range *clairLayers {
		err = postClairLayerV1(&cLayer)
		if err != nil {
			log.Printf("Failed to post layer %s (err: %s)", cLayer.Name, err)
			return nil, err
		}
	}

	features := make([]ClairFeature, 0)
	log.Print("Reading vulnerabilities from Clair")
	for _, cLayer := range *clairLayers {
		err = getClairLayerV1(&cLayer)
		for _, feature := range cLayer.Features {
			features = append(features, feature)
		}
		log.Printf("number of features %d", len(cLayer.Features))
		if err != nil {
			log.Printf("Failed to get layer %s (err: %s)", cLayer.Name, err)
			return nil, err
		}
	}

	log.Printf("Found %d affected features in scan", len(features))

	return &features, nil
}
