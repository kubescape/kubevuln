package process_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	yaml "gopkg.in/yaml.v3"

	wssc "github.com/armosec/armoapi-go/apis"
	cs "github.com/armosec/capacketsgo/containerscan"
	types "github.com/docker/docker/api/types"
)

var anchoreBinaryName = "/grype-cmd"
var anchoreDirectoryName = "/anchore-resources"
var anchoreDirectoryPath string
var mutex_edit_conf *sync.Mutex

type Application struct {
	ConfigPath         string
	Output             string  `mapstructure:"output"`
	OutputTemplateFile string  `mapstructure:"output-template-file"`
	ScopeOpt           Scope   `json:"-"`
	Scope              string  `mapstructure:"scope"`
	Quiet              bool    `mapstructure:"quiet"`
	Log                Logging `mapstructure:"log"`
	CliOptions         CliOnlyOptions
	Db                 Database    `mapstructure:"db"`
	Dev                Development `mapstructure:"dev"`
	CheckForAppUpdate  bool        `mapstructure:"check-for-app-update"`
	FailOn             string      `yaml:"-" mapstructure:"fail-on-severity"`
	FailOnSeverity     Severity    `yaml:"-" json:"-"`
	Registry           registry    `yaml:"registry" json:"registry" mapstructure:"registry"`
}

// Scope indicates "how" or from "which perspectives" the source object should be cataloged from.
type Scope string

const (
	// UnknownScope is the default scope
	UnknownScope Scope = "UnknownScope"
	// SquashedScope indicates to only catalog content visible from the squashed filesystem representation (what can be seen only within the container at runtime)
	SquashedScope Scope = "Squashed"
	// AllLayersScope indicates to catalog content on all layers, irregardless if it is visible from the container at runtime.
	AllLayersScope Scope = "AllLayers"
)

type Logging struct {
	Structured   bool   `mapstructure:"structured"`
	LevelOpt     Level  `json:"-"`
	Level        string `mapstructure:"level"`
	FileLocation string `mapstructure:"file"`
}

type Level uint32

type CliOnlyOptions struct {
	ConfigPath string
	Verbosity  int
}

type Database struct {
	Dir                   string `mapstructure:"cache-dir"`
	UpdateURL             string `mapstructure:"update-url"`
	AutoUpdate            bool   `mapstructure:"auto-update"`
	ValidateByHashOnStart bool   `mapstructure:"validate-by-hash-on-start"`
}

type Severity int

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
}

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority,omitempty"`
	// IMPORTANT: do not show the username in any YAML/JSON output (sensitive information)
	Username string `yaml:"username" json:"username" mapstructure:"username,omitempty"`
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"password" json:"password" mapstructure:"password,omitempty"`
	// IMPORTANT: do not show the token in any YAML/JSON output (sensitive information)
	Token string `yaml:"token" json:"token" mapstructure:"token,omitempty"`
}

type Development struct {
	ProfileCPU bool `mapstructure:"profile-cpu"`
}

type JSONReport struct {
	Matches    []Match      `json:"matches"`
	Source     *source      `json:"source"`
	Distro     distribution `json:"distro"`
	Descriptor descriptor   `json:"descriptor"`
}

type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

type Vulnerability struct {
	VulnerabilityMetadata
	Fix        Fix        `json:"fix"`
	Advisories []Advisory `json:"advisories"`
}

type VulnerabilityMetadata struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	URLs        []string `json:"urls"`
	Description string   `json:"description,omitempty"`
	Cvss        []Cvss   `json:"cvss"`
}

type Cvss struct {
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        CvssMetrics `json:"metrics"`
	VendorMetadata interface{} `json:"vendorMetadata"`
}

type CvssMetrics struct {
	BaseScore           float64  `json:"baseScore"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type Advisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type MatchDetails struct {
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"`
	Found      interface{} `json:"found"`
}

type SearchedByData struct {
	distro       Distro      `json:"distro"`
	namespace    string      `json:"namespace"`
	package_data PackageData `json:"packsge"`
}

type Distro struct {
	distro_type    string `json:"type"`
	distro_version string `json:"version"`
}

type PackageData struct {
	name    string `json:"name"`
	version string `json:"version"`
}

type Package struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      Type        `json:"type"`
	Locations []Location  `json:"locations"`
	Language  Language    `json:"language"`
	Licenses  []string    `json:"licenses"`
	CPEs      []string    `json:"cpes"`
	PURL      string      `json:"purl"`
	Metadata  interface{} `json:"metadata"`
}

type Type string

const (
	// the full set of supported packages
	UnknownPkg       Type = "UnknownPackage"
	ApkPkg           Type = "apk"
	GemPkg           Type = "gem"
	DebPkg           Type = "deb"
	RpmPkg           Type = "rpm"
	NpmPkg           Type = "npm"
	PythonPkg        Type = "python"
	JavaPkg          Type = "java-archive"
	JenkinsPluginPkg Type = "jenkins-plugin"
	GoModulePkg      Type = "go-module"
	RustPkg          Type = "rust-crate"
	KbPkg            Type = "msrc-kb"
)

type Location struct {
	RealPath     string    `json:"path"`              // The path where all path ancestors have no hardlinks / symlinks
	VirtualPath  string    `json:"-"`                 // The path to the file which may or may not have hardlinks / symlinks
	FileSystemID string    `json:"layerID,omitempty"` // An ID representing the filesystem. For container images this is a layer digest, directories or root filesystem this is blank.
	ref          Reference // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

// ID is used for file tree manipulation to uniquely identify tree nodes.
type ID uint64

// Path represents a file path
type Path string

// Reference represents a unique file. This is useful when path is not good enough (i.e. you have the same file path for two files in two different container image layers, and you need to be able to distinguish them apart)
type Reference struct {
	id       ID
	RealPath Path // file path with NO symlinks or hardlinks in constituent paths
}

type Language string

type source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type distribution struct {
	Name    string `json:"name"`    // Name of the Linux distribution
	Version string `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

type descriptor struct {
	Name                  string      `json:"name"`
	Version               string      `json:"version"`
	Configuration         interface{} `json:"configuration,omitempty"`
	VulnerabilityDbStatus interface{} `json:"db,omitempty"`
}

type TargetMapData struct {
	map_trget_data map[string]TargetData
}

type TargetData struct {
	UserInput      string          `json:"userInput"`
	ImageID        string          `json:"imageID"`
	ManifestDigest string          `json:"manifestDigest"`
	MediaType      string          `json:"mediaType"`
	Tags           []string        `json:"tags"`
	ImageSize      uint64          `json:"imageSize"`
	Layers         []AnchoreLayers `json:"layers"`
	Manifest       string          `json:"manifest"`
	Config         string          `json:"config"`
	RepoDigests    []string        `json:"repoDigests"`
}

type AnchoreLayers struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      uint64 `json:"size"`
}

func copyFileToOtherPath(src, dst string) error {
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		err = os.Chmod(dst, 0775)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateAnchoreResourcesDirectoryAndFiles() {

	mutex_edit_conf = &sync.Mutex{}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	anchoreDirectoryPath = dir + anchoreDirectoryName
	err = os.Mkdir(anchoreDirectoryPath, 0755)
	if err != nil {
		// log.Fatal(err)
	}

	err = os.Mkdir(anchoreDirectoryPath+"/.grype", 0755)
	if err != nil {
		// log.Fatal(err)
	}

	config_data := Application{
		CheckForAppUpdate: true,
		Output:            "json",
		Scope:             "Squashed",
		Quiet:             false,
		Log: Logging{
			Structured:   false,
			LevelOpt:     0,
			Level:        "trace",
			FileLocation: "",
		},
		Db: Database{
			AutoUpdate: true,
			Dir:        anchoreDirectoryPath + "/Db",
			UpdateURL:  "https://toolbox-data.anchore.io/grype/databases/listing.json",
		},
		Registry: registry{
			InsecureSkipTLSVerify: false,
			InsecureUseHTTP:       false,
			Auth:                  []RegistryCredentials{},
		},
	}
	config_yaml_data, err := yaml.Marshal(&config_data)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(anchoreDirectoryPath+"/.grype"+"/config.yaml", config_yaml_data, 0755)
	if err != nil {
		log.Fatal(err)
	}

	copyFileToOtherPath(dir+"/grype-cmd", anchoreDirectoryPath+anchoreBinaryName)

	err = os.Chdir(dir + anchoreDirectoryName)
	if err != nil {
		log.Fatal(err)
	}
}

func AddCredentialsToAnchoreConfiguratioFile(cred types.AuthConfig) error {
	var App Application

	mutex_edit_conf.Lock()

	bytes, err := ioutil.ReadFile(anchoreDirectoryPath + "/.grype/config.yaml")
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}

	if cred.Auth != "" {
		App.Registry.Auth = append(App.Registry.Auth, RegistryCredentials{Authority: cred.Auth})
	}
	if cred.RegistryToken != "" {
		App.Registry.Auth = append(App.Registry.Auth, RegistryCredentials{Token: cred.RegistryToken})
	}
	if cred.Username != "" && cred.Password != "" {
		App.Registry.Auth = append(App.Registry.Auth, RegistryCredentials{Username: cred.Username, Password: cred.Password})
	}
	if len(App.Registry.Auth) == 0 {
		/*
			should never happend
		*/
		return fmt.Errorf("error: no crediantials added")
	}

	config_yaml_data, err := yaml.Marshal(&App)
	err = ioutil.WriteFile(anchoreDirectoryPath+"/.grype"+"/config.yaml", config_yaml_data, 0755)
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}

	mutex_edit_conf.Unlock()
	return nil
}

func RemoveCredentialsFromAnchoreConfiguratioFile(cred types.AuthConfig) error {
	var App Application

	mutex_edit_conf.Lock()

	bytes, err := ioutil.ReadFile(anchoreDirectoryPath + "/.grype/config.yaml")
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}
	for i := 0; i < (len(App.Registry.Auth)); {

		if (cred.Username == App.Registry.Auth[i].Username) && (cred.Password == App.Registry.Auth[i].Password) || (cred.Auth == App.Registry.Auth[i].Authority) || (cred.IdentityToken == App.Registry.Auth[i].Token) {
			App.Registry.Auth = append(App.Registry.Auth[:i], App.Registry.Auth[i+1:]...)
			i--
		}
		i++
	}
	config_yaml_data, err := yaml.Marshal(&App)
	err = ioutil.WriteFile(anchoreDirectoryPath+"/.grype"+"/config.yaml", config_yaml_data, 0755)
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}

	mutex_edit_conf.Unlock()
	return nil
}

func GetAnchoreScanRes(scanCmd *wssc.WebsocketScanCommand) (*JSONReport, error) {

	vuln_anchore_report := &JSONReport{}
	var cmd *exec.Cmd
	if scanCmd.ImageHash != "" {
		cmd = exec.Command(anchoreDirectoryPath+anchoreBinaryName, "-vv", scanCmd.ImageHash, "-o", "json")
	} else {
		cmd = exec.Command(anchoreDirectoryPath+anchoreBinaryName, "-vv", scanCmd.ImageTag, "-o", "json")
	}
	var out bytes.Buffer
	var out_err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out_err

	for i := 0; i != len(scanCmd.Credentialslist); i++ {
		err := AddCredentialsToAnchoreConfiguratioFile(scanCmd.Credentialslist[i])
		if err != nil {
			return nil, err
		}
	}

	mutex_edit_conf.Lock()
	err := cmd.Run()
	mutex_edit_conf.Unlock()
	if err != nil {
		var err_str string
		var err_anchore_str string
		if len(out.Bytes()) != 0 {
			err_anchore_str = string(out.Bytes()[:])
		} else if len(out_err.Bytes()) != 0 {
			err_anchore_str = string(out_err.Bytes()[:])
		} else {
			err_anchore_str = "There is no verbose error from vuln scanner"
		}
		if werr, ok := err.(*exec.ExitError); ok {
			if s := werr.Sys().(syscall.WaitStatus); s != 0 {
				if s == 9 || (s == 1 && (strings.Contains(err_anchore_str, "failed to load vulnerability db: vulnerability database is corrupt") || strings.Contains(err_anchore_str, "UNAUTHORIZED: You don't have the needed permissions to perform this operation, and you may have invalid credentials."))) {
					err_str = fmt.Sprintf("failed vuln scanner for image: %s exit code %d :original error:: %v\n%v", scanCmd.ImageTag, s, err, err_anchore_str)
					err = fmt.Errorf(err_str)
				}
			}
		}
		return nil, err
	}

	for i := 0; i != len(scanCmd.Credentialslist); i++ {
		err = RemoveCredentialsFromAnchoreConfiguratioFile(scanCmd.Credentialslist[i])
		if err != nil {
			log.Println("failed to remove Credentials")
		}
	}

	json.Unmarshal(out.Bytes(), vuln_anchore_report)
	return vuln_anchore_report, nil
}

func convertToPkgFiles(fileList *[]string) *cs.PkgFiles {
	pkgFiles := make(cs.PkgFiles, 0)

	for _, file := range *fileList {
		filename := cs.PackageFile{Filename: file}
		pkgFiles = append(pkgFiles, filename)
	}

	return &pkgFiles
}

func GetPackagesInLayer(layer string, anchore_vuln_struct *JSONReport, packageManager PackageHandler) cs.LinuxPkgs {

	packages := make(cs.LinuxPkgs, 0)
	featureToFileList := make(map[string]*cs.PkgFiles)
	var pkgResolved map[string][]string //holds the mapping
	var Files *cs.PkgFiles
	linuxPackage := cs.LinuxPackage{}

	if packageManager != nil {

		for _, match_data := range anchore_vuln_struct.Matches {
			for _, match_detailes_data := range match_data.MatchDetails {
				if match_detailes_data.SearchedBy != nil {

					map_search_by_data := match_detailes_data.SearchedBy.(map[string]interface{})
					if map_search_by_data["package"] != nil {
						package_data := map_search_by_data["package"].(map[string]interface{})
						if package_data["name"] != nil {
							package_name := package_data["name"].(string)
							if files, ok := featureToFileList[package_name]; !ok {
								fileList, err := packageManager.readFileListForPackage(package_name)
								if err != nil {
									if fileList == nil {
										fileList = &[]string{}
										*fileList = make([]string, 0)
									}

									//see pkgResolved definition for more info
									if realPkgNames, isOk := pkgResolved[package_name]; packageManager.GetType() == "dpkg" && isOk {
										for _, pkgname := range realPkgNames {
											tmpfileList, err := packageManager.readFileListForPackage(pkgname)
											if err == nil {
												*fileList = append(*fileList, *tmpfileList...)
											}
										}
									} else {

										log.Printf("warning: package '%s', files not found even after remapping", package_name)
									}
								}

								if len(*fileList) > 0 {
									log.Printf("package %s added files", package_name)
									Files = convertToPkgFiles(fileList)
									linuxPackage.Files = *Files
									featureToFileList[package_name] = Files
								} else {
									log.Printf("warning: files not found")
								}
							} else {
								linuxPackage.Files = *files
							}
							linuxPackage.PackageName = package_name
						}
					}
				}
			}
		}
		packages = append(packages, linuxPackage)
	}

	return packages
}

func AnchoreStructConversion(anchore_vuln_struct *JSONReport) (*cs.LayersList, error) {
	layersList := make(cs.LayersList, 0)

	if anchore_vuln_struct.Source != nil {
		parentLayerHash := ""
		var map_target map[string]interface{}
		map_target = anchore_vuln_struct.Source.Target.(map[string]interface{})

		for _, l := range map_target["layers"].([]interface{}) {
			layer := l.(map[string]interface{})
			scanRes := cs.ScanResultLayer{
				LayerHash:       layer["digest"].(string),
				ParentLayerHash: parentLayerHash,
			}
			scanRes.Vulnerabilities = make(cs.VulnerabilitiesList, 0)
			parentLayerHash = layer["digest"].(string)
			for _, match := range anchore_vuln_struct.Matches {
				for _, location := range match.Artifact.Locations {
					if location.FileSystemID == layer["digest"].(string) {
						var version string
						var description string
						if len(match.Vulnerability.Fix.Versions) != 0 {
							version = match.Vulnerability.Fix.Versions[0]
						} else {
							version = ""
						}
						if len(match.RelatedVulnerabilities) != 0 {
							description = match.RelatedVulnerabilities[0].Description
						} else {
							description = ""
						}
						vuln := cs.Vulnerability{
							Name:               match.Vulnerability.ID,
							ImgHash:            map_target["manifestDigest"].(string),
							ImgTag:             map_target["userInput"].(string),
							RelatedPackageName: match.Artifact.Name,
							PackageVersion:     match.Artifact.Version,
							Link:               match.Vulnerability.DataSource,
							Description:        description,
							Severity:           match.Vulnerability.Severity,
							Fixes: []cs.FixedIn{
								cs.FixedIn{
									Name:    match.Vulnerability.Fix.State,
									ImgTag:  map_target["userInput"].(string),
									Version: version,
								},
							},
						}
						scanRes.Vulnerabilities = append(scanRes.Vulnerabilities, vuln)
						break
					}
				}
			}

			layersList = append(layersList, scanRes)
		}
	}

	return &layersList, nil
}

func GetAnchoreScanResults(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, error) {

	anchore_vuln_struct, err := GetAnchoreScanRes(scanCmd)
	if err != nil {
		return nil, err
	}

	LayersVulnsList, err := AnchoreStructConversion(anchore_vuln_struct)
	if err != nil {
		return nil, err
	}
	log.Println("after AnchoreStructConversion " + scanCmd.ImageTag)

	return LayersVulnsList, nil
}
