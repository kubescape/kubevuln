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
	"time"

	cs "asterix.cyberarmor.io/cyberarmor/capacketsgo/containerscan"
	"github.com/quay/claircore/pkg/cpe"
)

var clairUrl string
var clairUrlIndexer string
var clairUrlMatcher string
var getVulnsUsingMethod string

func init() {
	clairUrl = os.Getenv("CLAIR_URL")
	log.Printf("CLAIR_URL %v", clairUrl)
	if len(clairUrl) == 0 {
		log.Fatal("Must configure CLAIR_URL")
	}
	clairUrlIndexer = os.Getenv("CLAIR_URL_INDEXER")
	log.Printf("CLAIR_URL_INDEXER %v", clairUrlIndexer)
	if len(clairUrlIndexer) == 0 {
		clairUrlIndexer = clairUrl
	}
	clairUrlMatcher = os.Getenv("CLAIR_URL_MATCHER")
	log.Printf("CLAIR_URL_MATCHER %v", clairUrlMatcher)
	if len(clairUrlMatcher) == 0 {
		clairUrlMatcher = clairUrl
	}
	getVulnsUsingMethod = os.Getenv("GET_VULNS_METHOD")
	log.Printf("GET_VULNS_METHOD %v", getVulnsUsingMethod)
	if len(getVulnsUsingMethod) == 0 || getVulnsUsingMethod != "POST" {
		getVulnsUsingMethod = "GET"
	}

	// clairUrl = "http://172.17.0.5:6060"
}

type FixedIn struct {
	Name          string `json:"name,omitempty"`
	NamespaceName string `json:"namepaceName,omitempty"`
	Version       string `json:"version,omitempty"`
}

type VulFixes []FixedIn

type Layer struct {
	// Hash is a content addressable hash uniqely identifying this layer.
	// Libindex will treat layers with this same hash as identical.
	Hash           string              `json:"hash"`
	URI            string              `json:"uri"`
	Allow_redirect bool                `json:"allow_redirect,omitempty"`
	Headers        map[string][]string `json:"headers,omitempty"`

	// path to local file containing uncompressed tar archive of the layer's content
	// localPath string `json:"localPath,omitempty"`
}

type Manifest struct {
	// content addressable hash. should be able to be computed via
	// the hashes of all included layers
	Hash           string `json:"hash"`
	Allow_redirect bool   `json:"allow_redirect,omitempty"`
	// an array of filesystem layers indexed in the same order as the cooresponding image
	Layers []*Layer `json:"layers"`
}

type VulnerabilityReport struct {
	// the manifest hash this vulnerability report is describing
	Hash string `json:"manifest_hash"`
	// all discovered packages in this manifest keyed by package id
	Packages map[string]*Package `json:"packages"`
	// all discovered distributions in this manifest keyed by distribution id
	Distributions map[string]*Distribution `json:"distributions"`
	// all discovered repositories in this manifest keyed by repository id
	Repositories map[string]*Repository `json:"repository"`
	// a list of environment details a package was discovered in keyed by package id
	Environments map[string][]*Environment `json:"environments"`
	// all discovered vulnerabilities affecting this manifest
	Vulnerabilities map[string]*Vulnerability `json:"vulnerabilities"`
	// a lookup table associating package ids with 1 or more vulnerability ids. keyed by package id
	PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
}

type Severity uint

type ArchOp uint

type Range struct {
	Lower Version `json:"["`
	Upper Version `json:")"`
}

type Vulnerability struct {
	// unique ID of this vulnerability. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id"`
	// the updater that discovered this vulnerability
	Updater string `json:"updater"`
	// the name of the vulnerability. for example if the vulnerability exists in a CVE database this
	// would the unique CVE name such as CVE-2017-11722
	Name string `json:"name"`
	// the description of the vulnerability
	Description string `json:"description"`
	// the timestamp when vulnerability was issued
	Issued time.Time `json:"issued"`
	// any links to more details about the vulnerability
	Links string `json:"links"`
	// the severity string retrieved from the security database
	Severity string `json:"severity"`
	// a normalized Severity type providing client guaranteed severity information
	NormalizedSeverity string `json:"normalized_severity"`
	// the package information associated with the vulnerability. ideally these fields can be matched
	// to packages discovered by libindex PackageScanner structs.
	Package *Package `json:"package"`
	// the distribution information associated with the vulnerability.
	Dist *Distribution `json:"distribution,omitempty"`
	// the repository information associated with the vulnerability
	Repo *Repository `json:"repository,omitempty"`
	// a string specifying the package version the fix was released in
	FixedInVersion string `json:"fixed_in_version"`
	// Range describes the range of versions that are vulnerable.
	Range *Range `json:"range,omitempty"`
	// ArchOperation indicates how the affected Package's "arch" should be
	// compared.
	ArchOperation ArchOp `json:"arch_op,omitempty"`
}

type Environment struct {
	// the package database the associated package was discovered in
	PackageDB string `json:"package_db"`
	// the layer in which the associated package was introduced
	IntroducedIn string `json:"introduced_in"`
	// the ID of the distribution the package was discovered on
	DistributionID string `json:"distribution_id"`
	// the ID of the repository where this package was downloaded from (currently not used)
	RepositoryIDs []string `json:"repository_ids"`
}

type Repository struct {
	ID   string  `json:"id,omitempty"`
	Name string  `json:"name,omitempty"`
	Key  string  `json:"key,omitempty"`
	URI  string  `json:"uri,omitempty"`
	CPE  cpe.WFN `json:"cpe,omitempty"`
}

type Distribution struct {
	// unique ID of this distribution. this will be created as discovered by the library
	// and used for persistence and hash map indexes.
	ID string `json:"id"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system, excluding any version information
	// and suitable for processing by scripts or usage in generated filenames. Example: "DID=fedora" or "DID=debian".
	DID string `json:"did"`
	// A string identifying the operating system.
	// example: "Ubuntu"
	Name string `json:"name"`
	// A string identifying the operating system version, excluding any OS name information,
	// possibly including a release code name, and suitable for presentation to the user.
	// example: "16.04.6 LTS (Xenial Xerus)"
	Version string `json:"version"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system release code name,
	// excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames
	// example: "xenial"
	VersionCodeName string `json:"version_code_name"`
	// A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
	// identifying the operating system version, excluding any OS name information or release code name,
	// example: "16.04"
	VersionID string `json:"version_id"`
	// A string identifying the OS architecture
	// example: "x86_64"
	Arch string `json:"arch"`
	// Optional common platform enumeration identifier
	CPE cpe.WFN `json:"cpe"`
	// A pretty operating system name in a format suitable for presentation to the user.
	// May or may not contain a release code name or OS version of some kind, as suitable. If not set, defaults to "PRETTY_NAME="Linux"".
	// example: "PRETTY_NAME="Fedora 17 (Beefy Miracle)"".
	PrettyName string `json:"pretty_name"`
}

type Version struct {
	Kind string
	V    [10]int32
}

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind string `json:"kind,omitempty"`
	// if type is a binary package a source package maybe present which built this binary package.
	// must be a pointer to support recursive type:
	Source *Package `json:"source,omitempty"`
	// the file system path or prefix where this package resides
	PackageDB string `json:"-"`
	// a hint on which repository this package was downloaded from
	RepositoryHint string `json:"-"`
	// NormalizedVersion is a representation of a version string that's
	// correctly ordered when compared with other representations from the same
	// producer.
	NormalizedVersion string `json:"normalized_version,omitempty"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
	// CPE name for package
	CPE cpe.WFN `json:"cpe,omitempty"`
}

type IndexerReport struct {
	// the manifest hash this vulnerability report is describing
	Hash  string `json:"manifest_hash"`
	State string `json:"state"`
	// all discovered packages in this manifest keyed by package id
	Packages map[string]*Package `json:"packages"`
	// all discovered distributions in this manifest keyed by distribution id
	Distributions map[string]*Distribution `json:"distributions"`
	// all discovered repositories in this manifest keyed by repository id
	// Repositories map[string]*Repository `json:"repository"`
	// a list of environment details a package was discovered in keyed by package id
	Environments map[string][]*Environment `json:"environments"`
	// all discovered vulnerabilities affecting this manifest
	// Vulnerabilities map[string]*Vulnerability `json:"vulnerabilities"`
	// a lookup table associating package ids with 1 or more vulnerability ids. keyed by package id
	// PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
	Success bool   `json:"success"`
	Err     string `json:"err"`
}

func getLayerNameFromDigest(digest string) string {
	cp := strings.Index(digest, ":")
	if 0 < cp {
		return digest[cp+1:]
	}
	return digest
}

func convertToPkgFiles(fileList *[]string) *cs.PkgFiles {
	pkgFiles := make(cs.PkgFiles, 0)

	for _, file := range *fileList {
		filename := cs.PackageFile{Filename: file}
		pkgFiles = append(pkgFiles, filename)
	}

	return &pkgFiles
}

func ConvertManifestToClairPostIndexerReq(manifest *OciImageManifest) Manifest {
	clair_manifest := Manifest{}

	clair_manifest.Hash = manifest.Config.Digest

	clair_manifest.Layers = make([]*Layer, 0)
	for _, cLayer := range manifest.Layers {
		layer := Layer{}
		layer.Hash = cLayer.Digest
		layer.URI = cLayer.DownloadPath
		layer.Allow_redirect = true
		layer.Headers = make(map[string][]string)
		layer.Headers["Authorization"] = append(layer.Headers["Authorization"], cLayer.RequestOptions.Headers["Authorization"])
		clair_manifest.Layers = append(clair_manifest.Layers, &layer)
	}

	// print(clair_manifest)

	return clair_manifest
}

func updateUnknownSeverities(parsingVuln *VulnerabilityReport) {

	for _, vuln_data := range parsingVuln.Vulnerabilities {
		if vuln_data.NormalizedSeverity == "Unknown" {
			if strings.HasPrefix(vuln_data.Name, "CVE") {
				req, err := http.NewRequest("GET", "https://nvd.nist.gov/vuln/detail/"+vuln_data.Name, nil)
				if err != nil {
					log.Printf("failed to create get request to %v for getting severity err %v", vuln_data.Name, err)
					continue
				}
				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					log.Printf("failed to do get request to %v for getting severity err %v", vuln_data.Name, err)
					continue
				}
				htmlRaw, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				html := string(htmlRaw)
				if 0 < strings.Index(html, " CRITICAL") {
					vuln_data.NormalizedSeverity = "Critical"
					continue
				}
				if 0 < strings.Index(html, " HIGH") {
					vuln_data.NormalizedSeverity = "High"
					continue
				}
				if 0 < strings.Index(html, " MEDIUM") {
					vuln_data.NormalizedSeverity = "Medium"
					continue
				}
				if 0 < strings.Index(html, " LOW") {
					vuln_data.NormalizedSeverity = "Low"
					continue
				}
			}
		}
	}

}

func getVunurbilities(clair_manifest Manifest, imagetag string) (*VulnerabilityReport, error) {
	var parsingVuln VulnerabilityReport

	headers := map[string][]string{
		"Accept": []string{"application/json"},
	}

	req, err := http.NewRequest("GET", clairUrlMatcher+"/matcher/api/v1/vulnerability_report/"+clair_manifest.Hash, nil)
	req.Header = headers
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("image %v: getVunurbilities: Get requests from the matcher failed with error %v", imagetag, err)
		return nil, err
	}

	jsonRaw, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(jsonRaw, &parsingVuln)
	if err == nil {
		log.Printf("image %v: getVunurbilities: get vuln from matcher succeed", imagetag)
	} else {
		fmt.Errorf("error %s", err)
		log.Printf("image %v: getVunurbilities: while get vuln from matcher ", imagetag, err)
		return nil, err
	}

	updateUnknownSeverities(&parsingVuln)

	log.Printf("image %v: getVunurbilities: number of vulns %v", imagetag, len(parsingVuln.Vulnerabilities))
	return &parsingVuln, nil
}

func getVunurbilitiesUsingPOST(clair_manifest Manifest, indexRepList *IndexerReport) (*VulnerabilityReport, error) {
	var parsingVuln VulnerabilityReport

	headers := map[string][]string{
		"Accept": []string{"application/json"},
	}

	jsonReq, err := json.Marshal(*indexRepList)

	data := bytes.NewBuffer(jsonReq)
	req, err := http.NewRequest("POST", clairUrlMatcher+"/matcher/api/v1/vulnerability_report/"+clair_manifest.Hash, data)
	if err != nil {
		log.Printf("fail to create post to indexer request error %v", err)
		return nil, err
	}

	req.Header = headers
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed posting request to indexer error %v", err)
		return nil, err
	}

	jsonRaw, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(jsonRaw, &parsingVuln)
	if err == nil {
		log.Printf("getVunurbilitiesUsingPOST: get vuln from matcher succeed")
	} else {
		fmt.Errorf("error %s", err)
		log.Printf("getVunurbilitiesUsingPOST: while get vuln from matcher ", err)
		return nil, err
	}

	log.Printf("getVunurbilitiesUsingPOST: number of vulns %v", len(parsingVuln.Vulnerabilities))
	return &parsingVuln, nil
}

func ConvertClairVulnStructToOurStruct(indexReport *IndexerReport, vulnReport *VulnerabilityReport, packageManager PackageHandler, manifes_clair_format Manifest) *cs.LayersList {
	parentLayerHash := ""
	layersList := make(cs.LayersList, 0)
	featureToFileList := make(map[string]*cs.PkgFiles)

	var pkgResolved map[string][]string //holds the mapping
	if packageManager != nil && packageManager.GetType() == "dpkg" {
		file, err := packageManager.GetOCIMage().GetFile("/var/lib/dpkg/status")
		if err == nil {
			pkgResolved, err = clairPkgName2packagename(packageManager.GetType(), *file)
		}
		// pass file

	}

	for _, layer := range manifes_clair_format.Layers {
		vuln_list := make(cs.VulnerabilitiesList, 0)
		var Files *cs.PkgFiles
		linuxPackage := cs.LinuxPackage{}

		layersData := cs.ScanResultLayer{
			LayerHash:       layer.Hash,
			ParentLayerHash: parentLayerHash,
		}

		for package_id, vuln_res_list := range vulnReport.PackageVulnerabilities {
			for vuln_id, vuln_data := range vulnReport.Vulnerabilities {
				for _, vuln_inner_id := range vuln_res_list {
					if vuln_inner_id == vuln_id {
						for _, env_data := range vulnReport.Environments[package_id] {
							if layer.Hash == env_data.IntroducedIn {
								vuln := cs.Vulnerability{
									Name:               vuln_data.Name,
									ImgHash:            manifes_clair_format.Hash,
									ImgTag:             "",
									RelatedPackageName: vuln_data.Package.Name,
									PackageVersion:     "",
									Link:               vuln_data.Links,
									Description:        vuln_data.Description,
									Severity:           vuln_data.NormalizedSeverity,
									Fixes: []cs.FixedIn{
										cs.FixedIn{
											Name:    "",
											ImgTag:  "",
											Version: vuln_data.FixedInVersion,
										},
									},
								}
								vuln_list = append(vuln_list, vuln)
							}
						}
					}
				}
			}
		}

		if packageManager != nil {
			for _, package_data := range vulnReport.Packages {
				if files, ok := featureToFileList[package_data.Name]; !ok {
					fileList, err := packageManager.readFileListForPackage(package_data.Name)
					if err != nil {
						if fileList == nil {
							fileList = &[]string{}
							*fileList = make([]string, 0)
						}

						//see pkgResolved definition for more info
						if realPkgNames, isOk := pkgResolved[package_data.Name]; packageManager.GetType() == "dpkg" && isOk {
							for _, pkgname := range realPkgNames {
								tmpfileList, err := packageManager.readFileListForPackage(pkgname)
								if err == nil {
									*fileList = append(*fileList, *tmpfileList...)
								}
							}
						} else {

							log.Printf("package %s failed: no files found even after remapping", package_data.Name)
						}
					}

					if len(*fileList) > 0 {
						log.Printf("package %s added files", package_data.Name)
						Files = convertToPkgFiles(fileList)
						linuxPackage.Files = *Files
						featureToFileList[package_data.Name] = Files
					} else {
						log.Printf("error no files found")
					}
				} else {
					linuxPackage.Files = *files
				}
				linuxPackage.PackageName = package_data.Name
			}
			layersData.Packages = append(layersData.Packages, linuxPackage)
		}

		layersData.Vulnerabilities = vuln_list
		layersList = append(layersList, layersData)

		parentLayerHash = layer.Hash
	}

	return &layersList
}

func GetClairScanResultsByLayerV4(manifest *OciImageManifest, packageManager PackageHandler, imagetag string) (*cs.LayersList, error) {

	manifes_clair_format := ConvertManifestToClairPostIndexerReq(manifest)

	indexerReport, err := IndexManifestContents(manifes_clair_format, imagetag)
	if err != nil {
		return nil, err
	}

	var vulnsReport *VulnerabilityReport
	switch getVulnsUsingMethod {
	case "GET":
		vulnsReportTemp, err := getVunurbilities(manifes_clair_format, imagetag)
		if err != nil {
			return nil, err
		}
		vulnsReport = vulnsReportTemp
	case "POST":
		vulnsReportTemp, err := getVunurbilitiesUsingPOST(manifes_clair_format, indexerReport)
		if err != nil {
			return nil, err
		}
		vulnsReport = vulnsReportTemp
	}

	layersList := ConvertClairVulnStructToOurStruct(indexerReport, vulnsReport, packageManager, manifes_clair_format)

	return layersList, err
}

func IndexManifestContents(clair_manifest Manifest, imagetag string) (*IndexerReport, error) {

	parsingLayers := make([]IndexerReport, 0)

	Layers := make([]*Layer, 0)
	postManifest := Manifest{
		Hash:           clair_manifest.Hash,
		Allow_redirect: true,
	}

	authorization := []string{}
	for _, cLayer := range clair_manifest.Layers {

		authorization = append(authorization, cLayer.Headers["Authorization"][0])
		headers := map[string][]string{
			"Content-Type":  []string{"application/json"},
			"Accept":        []string{"application/json"},
			"Authorization": []string{authorization[0]},
		}
		layer := &Layer{
			Hash: cLayer.Hash,
			URI:  cLayer.URI,
			// Allow_redirect: true,
			Headers: headers,
		}
		Layers = append(Layers, layer)

	}

	header := map[string][]string{
		"Content-Type":  []string{"application/json"},
		"Accept":        []string{"application/json"},
		"Authorization": []string{authorization[0]},
	}
	postManifest.Layers = Layers
	// postManifest.Hash = "sha256:dc95f357f226415aced988a213fb5c1e45e1a6d202e38e2951a4618e14111111"
	jsonReq, err := json.Marshal(postManifest)

	data := bytes.NewBuffer(jsonReq)
	req, err := http.NewRequest("POST", clairUrlIndexer+"/indexer/api/v1/index_report", data)
	if err != nil {
		log.Printf("fail to create post to indexer request error %v", err)
		return nil, err
	}

	req.Header = header
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed posting request to indexer error %v", err)
		return nil, err
	}
	jsonRaw, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("failed posting request to indexer error %v body %v", resp.Status, string(jsonRaw))
		return nil, fmt.Errorf("%v %v", resp.Status, string(jsonRaw))
	}
	var parsingLayer IndexerReport
	err = json.Unmarshal(jsonRaw, &parsingLayer)
	if err == nil && parsingLayer.Success == true && parsingLayer.State == "IndexFinished" {
		log.Printf("image %v: finished parsing indexer response successfully and indexing is finished", imagetag)
		parsingLayers = append(parsingLayers, parsingLayer)
	} else if err == nil && parsingLayer.Success == true {
		log.Printf("image %v: finished parsing indexer response successfully index State %s index error %s", imagetag, parsingLayer.State, parsingLayer.Err)
		//waitTillIndexIsFinished()
	} else if err == nil && parsingLayer.Success == false {
		log.Printf("image %v: error from indexer respons index State %s index error %s", imagetag, parsingLayer.State, parsingLayer.Err)
		//waitTillIndexIsFinished()
		return nil, fmt.Errorf("indexer request failed")
	} else {
		log.Printf("image %v: failed parsing indexer response error %v", imagetag, err)
		return nil, err
	}

	println(parsingLayer.Err)
	println(resp.StatusCode)
	println(resp.Status)

	return &parsingLayer, nil
}
