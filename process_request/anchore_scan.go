package process_request

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/xyproto/randomstring"
	yaml "gopkg.in/yaml.v3"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"

	"github.com/anchore/grype/grype/presenter/models"
	types "github.com/docker/docker/api/types"
	containerTypes "github.com/google/go-containerregistry/pkg/v1"
)

const (
	urlBase                      = "http://localhost:8080"
	defaultDbUpdateTimeInMinutes = 60 * 6
	DbIsReady                    = "db is ready"
	anchoreBinaryName            = "grype-cmd"
	anchoreDirectoryName         = "anchore-resources"

	anchoreConfigFileName      = "config.yaml"
	anchoreConfigDirectoryName = ".grype"
)

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
	Dir                   string `yaml:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL             string `yaml:"update-url" mapstructure:"update-url"`
	AutoUpdate            bool   `yaml:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart bool   `yaml:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
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

func CreateAnchoreResourcesDirectoryAndFiles() {

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	anchoreDirectoryPath = path.Join(dir, anchoreDirectoryName)
}

func SetHTTPScansToAnchoreConfigurationFile(configFilePath string, useHTTP bool) error {
	var App Application

	bytes, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
		return err
	}

	App.Registry.InsecureUseHTTP = useHTTP
	config_yaml_data, _ := yaml.Marshal(&App)
	err = ioutil.WriteFile(configFilePath, config_yaml_data, 0755)
	if err != nil {
		return err
	}

	return nil
}
func SetSkipTLSVerifyToAnchoreConfigurationFile(configFilePath string, skipVerify bool) error {
	var App Application

	bytes, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
		return err
	}

	App.Registry.InsecureSkipTLSVerify = skipVerify
	config_yaml_data, _ := yaml.Marshal(&App)
	err = ioutil.WriteFile(configFilePath, config_yaml_data, 0755)
	if err != nil {
		return err
	}

	return nil
}

func AddCredentialsToAnchoreConfigurationFile(configFilePath string, cred types.AuthConfig) error {
	var App Application

	bytes, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
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
		return fmt.Errorf("no credentials added")
	}

	config_yaml_data, _ := yaml.Marshal(&App)
	err = ioutil.WriteFile(configFilePath, config_yaml_data, 0755)
	if err != nil {
		return err
	}

	return nil
}

func RemoveCredentialsFromAnchoreConfiguratioFile(cred types.AuthConfig) error {
	var App Application

	mutex_edit_conf.Lock()

	bytes, err := ioutil.ReadFile(path.Join(anchoreDirectoryPath, anchoreConfigDirectoryName, anchoreConfigFileName))
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
	config_yaml_data, _ := yaml.Marshal(&App)
	err = ioutil.WriteFile(path.Join(anchoreDirectoryPath, anchoreConfigDirectoryName, anchoreConfigFileName), config_yaml_data, 0755)
	if err != nil {
		mutex_edit_conf.Unlock()
		return err
	}

	mutex_edit_conf.Unlock()
	return nil
}

func copyFileData(anchoreConfigPath string) error {
	source, err := os.Open(path.Join(anchoreDirectoryPath, anchoreConfigDirectoryName, anchoreConfigFileName))
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(anchoreConfigPath)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func GetAnchoreScanRes(scanCmd *wssc.WebsocketScanCommand) (*models.Document, error) {

	configFileName := randomstring.HumanFriendlyEnglishString(rand.Intn(100)) + ".yaml"
	anchoreConfigPath := path.Join(anchoreDirectoryPath, anchoreConfigDirectoryName, configFileName)
	err := copyFileData(anchoreConfigPath)
	if err != nil {
		log.Printf("failed to copy default file config to %v with err %v\n", anchoreConfigPath, err)
		return nil, err
	}

	for i := 0; i != len(scanCmd.Credentialslist); i++ {
		err := AddCredentialsToAnchoreConfigurationFile(anchoreConfigPath, scanCmd.Credentialslist[i])
		if err != nil {
			return nil, err
		}
	}
	if val, ok := scanCmd.Args[armotypes.AttributeUseHTTP]; ok && val.(bool) {
		SetHTTPScansToAnchoreConfigurationFile(anchoreConfigPath, true)
	}
	if val, ok := scanCmd.Args[armotypes.AttributeSkipTLSVerify]; ok && val.(bool) {
		SetSkipTLSVerifyToAnchoreConfigurationFile(anchoreConfigPath, true)
	}

	cmd, imageID, out, out_err := executeAnchoreCommand(scanCmd, anchoreConfigPath)

	log.Printf("sending command to vuln scan Binary image: %s, wlid: %s", imageID, scanCmd.Wlid)
	err = cmd.Run()
	if err != nil {

		err_str, err_anchore_str, exit_code := anchoreErrorHandler(out, out_err, err)
		if strings.Contains(err_anchore_str, "server gave HTTP response to HTTPS client") || strings.Contains(err_str, "server gave HTTP response to HTTPS client") {
			log.Printf("trying to scan image %s via HTTP and not HTTPS", imageID)
			if err = SetHTTPScansToAnchoreConfigurationFile(anchoreConfigPath, true); err == nil {
				cmd, imageID, out, out_err = executeAnchoreCommand(scanCmd, anchoreConfigPath)
				err = cmd.Run()
				_, err_anchore_str, exit_code = anchoreErrorHandler(out, out_err, err)
				if err == nil {
					return createAnchoreReport(anchoreConfigPath, out, out_err)
				}

			}
		}
		err_str = fmt.Sprintf("failed vuln scanner for image: %s exit code %s :original error:: %v\n%v\n troubleshooting in the following link: https://hub.armo.cloud/docs/limitations", imageID, exit_code, err, err_anchore_str)
		err = fmt.Errorf(err_str)
		os.Remove(anchoreConfigPath)
		return nil, err
	}

	return createAnchoreReport(anchoreConfigPath, out, out_err)
}

func createAnchoreReport(anchoreConfigPath string, out *bytes.Buffer, out_err *bytes.Buffer) (*models.Document, error) {
	vuln_anchore_report := &models.Document{}
	err := os.Remove(anchoreConfigPath)
	if err != nil {
		log.Printf("fail to remove %v with err %v\n", anchoreConfigPath, err)
		return nil, err
	}
	err = json.Unmarshal(out.Bytes(), vuln_anchore_report)

	if err != nil {
		err = fmt.Errorf("json unmarshall failed with an error: %s\n vuln scanner error: %s", err.Error(), string(out_err.Bytes()[:]))
		return nil, err
	}
	return vuln_anchore_report, nil
}

func parseLayersPayload(target interface{}) map[string]cs.ESLayer {
	jsonConfig := &containerTypes.ConfigFile{}
	config := target.(map[string]interface{})["config"].(string)
	valueConfig, _ := b64.StdEncoding.DecodeString(config)

	json.Unmarshal([]byte(valueConfig), jsonConfig)
	listLayers := make([]cs.ESLayer, 0)
	layerMap := make(map[string]cs.ESLayer)

	for i := range jsonConfig.History {

		if !jsonConfig.History[i].EmptyLayer {
			listLayers = append(listLayers, cs.ESLayer{LayerInfo: &cs.LayerInfo{
				CreatedBy:   jsonConfig.History[i].CreatedBy,
				CreatedTime: &jsonConfig.History[i].Created.Time,
			},
			})
		}
	}
	for i := 0; i < len(listLayers) && i < len(jsonConfig.RootFS.DiffIDs); i++ {
		listLayers[i].LayerHash = jsonConfig.RootFS.DiffIDs[i].String()
		if i > 0 {
			listLayers[i].ParentLayerHash = jsonConfig.RootFS.DiffIDs[i-1].String()
			listLayers[i].LayerInfo.LayerOrder = i
		}
		layerMap[listLayers[i].LayerHash] = listLayers[i]
	}

	return layerMap
}

func executeAnchoreCommand(scanCmd *wssc.WebsocketScanCommand, anchoreConfigPath string) (*exec.Cmd, string, *bytes.Buffer, *bytes.Buffer) {
	var cmd *exec.Cmd
	var imageID string

	anchoreBinaryFullPath := path.Join(anchoreDirectoryPath, anchoreBinaryName)
	if scanCmd.ImageHash != "" {
		cmd = exec.Command(anchoreBinaryFullPath, "-vv", scanCmd.ImageHash, "-o", "json", "-c", anchoreConfigPath)
		imageID = scanCmd.ImageHash
	} else {
		cmd = exec.Command(anchoreBinaryFullPath, "-vv", scanCmd.ImageTag, "-o", "json", "-c", anchoreConfigPath)
		imageID = scanCmd.ImageTag
	}
	var out bytes.Buffer
	var out_err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out_err
	return cmd, imageID, &out, &out_err
}

func anchoreErrorHandler(out *bytes.Buffer, out_err *bytes.Buffer, err error) (string, string, string) {
	var err_str string
	var err_anchore_str string
	if len(out.Bytes()) != 0 {
		err_anchore_str = string(out.Bytes()[:])
	} else if len(out_err.Bytes()) != 0 {
		err_anchore_str = string(out_err.Bytes()[:])
	} else {
		err_anchore_str = "There is no verbose error from vuln scanner"
	}
	exit_code := "unknown"
	if werr, ok := err.(*exec.ExitError); ok {
		if s := werr.Sys().(syscall.WaitStatus); s != 0 {
			exit_code = fmt.Sprintf("%d", s)
		}
	}
	return err_str, err_anchore_str, exit_code
}

func getCVEExceptionMatchCVENameFromList(srcCVEList []armotypes.VulnerabilityExceptionPolicy, CVEName string) ([]armotypes.VulnerabilityExceptionPolicy, bool) {
	var l []armotypes.VulnerabilityExceptionPolicy

	for i := range srcCVEList {
		for j := range srcCVEList[i].VulnerabilityPolicies {
			if srcCVEList[i].VulnerabilityPolicies[j].Name == CVEName {
				l = append(l, srcCVEList[i])
			}
		}
	}

	if len(l) > 0 {
		return l, true
	}
	return nil, false
}

func AnchoreStructConversion(anchore_vuln_struct *models.Document, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) (*cs.LayersList, error) {
	layersList := make(cs.LayersList, 0)

	if anchore_vuln_struct.Source != nil {
		parentLayerHash := ""
		map_target := anchore_vuln_struct.Source.Target.(map[string]interface{})

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
								{
									Name:    match.Vulnerability.Fix.State,
									ImgTag:  map_target["userInput"].(string),
									Version: version,
								},
							},
						}
						if cveExceptions, ok := getCVEExceptionMatchCVENameFromList(vulnerabilityExceptionPolicyList, vuln.Name); ok {
							vuln.ExceptionApplied = cveExceptions
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

func GetCVEExceptions(scanCmd *wssc.WebsocketScanCommand) ([]armotypes.VulnerabilityExceptionPolicy, error) {

	backendURL := os.Getenv(BackendUrlEnvironmentVariable)
	if backendURL == "" {
		return nil, fmt.Errorf("GetCVEExceptions: failed, you must provide the backend URL in the armor backend config map")
	}
	designator := armotypes.PortalDesignator{
		DesignatorType: armotypes.DesignatorAttribute,
		Attributes: map[string]string{
			"customerGUID":        os.Getenv(CustomerGuidEnvironmentVariable),
			"scope.cluster":       wlidpkg.GetClusterFromWlid(scanCmd.Wlid),
			"scope.namespace":     wlidpkg.GetNamespaceFromWlid(scanCmd.Wlid),
			"scope.kind":          strings.ToLower(wlidpkg.GetKindFromWlid(scanCmd.Wlid)),
			"scope.name":          wlidpkg.GetNameFromWlid(scanCmd.Wlid),
			"scope.containerName": scanCmd.ContainerName,
		},
	}

	vulnExceptionList, err := wssc.BackendGetCVEExceptionByDEsignator(backendURL, os.Getenv(CustomerGuidEnvironmentVariable), &designator)
	if err != nil {
		return nil, err
	}

	return vulnExceptionList, nil
}

func GetAnchoreScanResults(scanCmd *wssc.WebsocketScanCommand) (*cs.LayersList, map[string]cs.ESLayer, error) {

	anchore_vuln_struct, err := GetAnchoreScanRes(scanCmd)
	if err != nil {
		return nil, nil, err
	}
	exceptions, err := GetCVEExceptions(scanCmd)
	if err != nil {
		log.Println(scanCmd.ImageTag + " no cve exceptions found")
	}
	preparedLayers := parseLayersPayload(anchore_vuln_struct.Source.Target)
	LayersVulnsList, err := AnchoreStructConversion(anchore_vuln_struct, exceptions)
	if err != nil {
		return nil, nil, err
	}
	log.Println("after AnchoreStructConversion " + scanCmd.ImageTag)

	return LayersVulnsList, preparedLayers, nil
}

func HandleAnchoreDBUpdate(uri, serverReady string) {

	DBCommands := make(map[string]interface{})
	update_wait_time, err := strconv.Atoi(os.Getenv(DbUpdateWaitTimeMinutesEnvironmentVariable))
	if err != nil {
		update_wait_time = defaultDbUpdateTimeInMinutes
	}

	for {
		fullURL := urlBase + serverReady
		req, err := http.NewRequest(http.MethodHead, fullURL, nil)
		if err != nil {
			fmt.Println("fail create http request with err:", err)
		}
		fmt.Println("check if vuln scan server ready")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("server ready: response create err:", err)
		}
		if resp != nil {
			fmt.Println("server ready: response Status:", resp.Status)
			resp.Body.Close()
		}
		if resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Println("server is ready")
			break
		} else {
			fmt.Println("server is not yet ready, wait 5 secs before check again")
			time.Sleep(time.Second * 5)
		}
	}

	for {
		DBCommands["updateDB"] = ""
		commandDB := wssc.DBCommand{
			Commands: DBCommands,
		}
		buf, err := json.Marshal(commandDB)
		if err == nil {
			fullURL := urlBase + uri
			req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(buf))
			if err != nil {
				fmt.Println("fail create http request with err:", err)
			}
			req.Header.Set("Content-Type", "application/json; charset=UTF-8")

			fmt.Println("start db update")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println("response create err:", err)
			}
			if resp != nil {
				fmt.Println("db update: response Status:", resp.Status)
				resp.Body.Close()
			}
		} else {
			fmt.Println("HandleAnchoreDBUpdate: fail marshal ", err)
		}

		timer := time.NewTimer(time.Duration(update_wait_time) * time.Minute)
		<-timer.C
	}

}

func informDatabaseIsReadyToUse() {
	ServerReadyURI := "/" + wssc.WebsocketScanCommandVersion + "/" + wssc.ServerReady
	fullURL := urlBase + ServerReadyURI
	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer([]byte(DbIsReady)))
	if err != nil {
		fmt.Println("fail create http request with err:", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("response create err:", err)
	}
	if resp != nil {
		fmt.Println("database of server ready: response Status:", resp.Status)
		resp.Body.Close()
	}
}

func StartUpdateDB(payload interface{}) (interface{}, error) {
	var out bytes.Buffer
	var out_err bytes.Buffer

	anchoreConfigPath := path.Join(anchoreDirectoryPath, anchoreConfigDirectoryName, anchoreConfigFileName)
	anchoreBinaryFullPath := path.Join(anchoreDirectoryPath, anchoreBinaryName)

	cmd := exec.Command(anchoreBinaryFullPath, "db", "update", "-vv", "-c", anchoreConfigPath)
	cmd.Stdout = &out
	cmd.Stderr = &out_err

	log.Printf("handle update DB command")
	err := cmd.Run()
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
		exit_code := "unknown"
		if werr, ok := err.(*exec.ExitError); ok {
			if s := werr.Sys().(syscall.WaitStatus); s != 0 {
				exit_code = fmt.Sprintf("%d", s)
			}
		}
		log.Printf("failed update CVE DB exit code %s :original error:: %v\n%v\n", exit_code, err, err_anchore_str)
		log.Printf("DB update: string(out.Bytes()[:]) %v\nstring(out_err.Bytes()[:]) %v", string(out.Bytes()[:]), string(out_err.Bytes()[:]))
		err = fmt.Errorf(err_str)
		return nil, err
	}

	log.Printf("DB updated successfully")
	informDatabaseIsReadyToUse()
	return nil, nil
}
