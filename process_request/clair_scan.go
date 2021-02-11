package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	cs "asterix.cyberarmor.io/cyberarmor/capacketsgo/containerscan"
)

var clairUrl string

func init() {
	clairUrl = os.Getenv("CLAIR_URL")
	if len(clairUrl) == 0 {
		log.Fatal("Must configure CLAIR_URL")
	}

	// clairUrl = "http://172.17.0.5:6060"
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

type FixedIn struct {
	Name 			string `json:"name,omitempty"`
	NamespaceName 	string `json:"namepaceName,omitempty"`
	Version 		string `json:"version,omitempty"`
}

type VulFixes []FixedIn

type ClairVulnerability struct {
	Name         string 		`json:"name,omitempty"`
	NamepaceName string 		`json:"namepaceName,omitempty"`
	Description  string 		`json:"description,omitempty"`
	Link         string 		`json:"link,omitempty"`
	Severity     string 		`json:"severity,omitempty"`
	Metadata     interface{} 	`json:"metadata",omitempty`
	Fixes        VulFixes    	`json:"fixedIn",omitempty`
}

type EnclosedClairLayer struct {
	Layer ClairLayer
}

type EnclosedClairVulnerabilityEventRecieverVersion struct {
	Vulnerability ClairVulnerability
}

type ClairVulnerabilty struct {
	Name         string `json:"name,omitempty"`
	NamepaceName string `json:"namepaceName,omitempty"`
	Description  string `json:"description,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Link         string `json:"link,omitempty"`
	FixedBy		 string `json:"fixedBy,omitempty"`
	Relevance    string `json:"relevance,omitempty"`
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

func getClairLayerV1FeatureAndVulnerabilities(layer_name string, layer *ClairLayer) error {
	resp, err := http.Get(clairUrl + "/v1/layers/" + layer_name + "?features&vulnerabilities")
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

func getClairLayerVulnerabilitiesV1(vulnerability *ClairVulnerability, namespace string, vulnerabilityname string) error {
	resp, err := http.Get(clairUrl + "/v1/namespaces/" + namespace + "/vulnerabilities/" + vulnerabilityname + "?fixedIn")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 299 < resp.StatusCode {
		return fmt.Errorf("clair get vulnerability failed with %d", resp.StatusCode)
	}
	// log.Printf("Got layer %s to Clair with code %d", layer.Name, resp.StatusCode)
	jsonRaw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	parsingVulnerability := EnclosedClairVulnerabilityEventRecieverVersion{}
	err = json.Unmarshal(jsonRaw, &parsingVulnerability)
	if err == nil {
		*vulnerability = parsingVulnerability.Vulnerability
	}

	return err
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

func convertToPkgFiles(fileList *[]string) (*cs.PkgFiles){
	pkgFiles := make(cs.PkgFiles, 0)

	for _, file := range *fileList {
		filename := cs.PackageFile{Filename: file}
		pkgFiles = append(pkgFiles, filename)
	}

	return &pkgFiles
}

func GetClairScanResultsByLayer(manifest *OciImageManifest, packageHandler PackageHandler, imagetag string) (*cs.LayersList, error) {
	var clairLayers *[]ClairLayer
	var err error
	featureToFileList := make(map[string]*cs.PkgFiles)

	clairLayers = createClairLayersFromOciManifest(manifest)
	log.Printf("Posting layers for %s to Clair", manifest.Config.Digest)
	for _, cLayer := range *clairLayers {
		err = postClairLayerV1(&cLayer)
		if err != nil {
			log.Printf("Failed to post layer %s (err: %s)", cLayer.Name, err)
			return nil, err
		}
	}

	ClairLayerWithVulns := make([]*ClairLayer, 0)
	for _, cLayer := range *clairLayers {
		layer_data := ClairLayer{}
		err = getClairLayerV1FeatureAndVulnerabilities(cLayer.Name, &layer_data)
		if err != nil {
			log.Printf("Failed to get layer %s (err: %s)", cLayer.Name, err)
			return nil, err
		}
		ClairLayerWithVulns = append(ClairLayerWithVulns, &layer_data)
	}

	layersList := make(cs.LayersList, 0)
	log.Print("Reading vulnerabilities from Clair")
	for _, cLayer := range ClairLayerWithVulns {
		layerRes := cs.ScanResultLayer{
			LayerHash: 			cLayer.Name,
			ParentLayerHash: 	cLayer.ParentName}
		vulnerabilities := make(cs.VulnerabilitiesList, 0)
		for _, feature := range cLayer.Features {
			linuxPackage := cs.LinuxPackage{}
			if (len(feature.Vulnerabilities) != 0) {
				for _, vuln := range feature.Vulnerabilities {
					// we need to use this function in oredr to get more detailed data 
					clairVulnerability := ClairVulnerability{}
					err = getClairLayerVulnerabilitiesV1(&clairVulnerability, cLayer.NamespaceName, vuln.Name)
					if err == nil {
						namespacename := imagetag
						if clairVulnerability.NamepaceName != "" && clairVulnerability.NamepaceName != imagetag {
							log.Printf("namespace name getting from clair is different from image tag %s != %s", imagetag, clairVulnerability.NamepaceName)
						}
						vulnerability := cs.Vulnerability{
							Name: clairVulnerability.Name,
							ImgHash: "",
							ImgTag: namespacename,
							RelatedPackageName: feature.Name,
							PackageVersion: feature.Version,
							Link: clairVulnerability.Link,
							Description: clairVulnerability.Description,
							Severity: clairVulnerability.Severity,
							Metadata: clairVulnerability.Metadata}
						if clairVulnerability.Fixes != nil {
							VulFixes := cs.VulFixes{}
							for _, fix := range clairVulnerability.Fixes {
								fixOurVersion := cs.FixedIn{
									Name: fix.Name,
									ImgTag: namespacename,
									Version: fix.Version}
								VulFixes = append(VulFixes, fixOurVersion)
							}
							vulnerability.Fixes = VulFixes
						}
						vulnerabilities = append(vulnerabilities, vulnerability)
					}
				}
			}
			var Files *cs.PkgFiles
			if files, ok:= featureToFileList[feature.Name]; !ok {
				fileList, err := packageHandler.readFileListForPackage(feature.Name)
				if (err != nil){
					log.Printf("Not found file list for package %s", feature.Name)
				} else {
					Files = convertToPkgFiles(fileList)
					linuxPackage.Files = *Files
					featureToFileList[feature.Name] = Files
				}
			} else {
				linuxPackage.Files = *files
			}
			linuxPackage.PackageName = feature.Name

			layerRes.Packages = append(layerRes.Packages, linuxPackage)
		}

		layerRes.Vulnerabilities = vulnerabilities			
		layersList = append(layersList, layerRes)
	}

	return &layersList, err
}
