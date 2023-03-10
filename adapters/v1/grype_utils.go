package v1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
)

func getMatchers() []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{MavenBaseURL: "https://search.maven.org/solrsearch/select"},
				UseCPEs:              true,
			},
			Ruby:       ruby.MatcherConfig{UseCPEs: true},
			Python:     python.MatcherConfig{UseCPEs: true},
			Dotnet:     dotnet.MatcherConfig{UseCPEs: true},
			Javascript: javascript.MatcherConfig{UseCPEs: true},
			Golang:     golang.MatcherConfig{UseCPEs: true},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}

func getCVEExceptionMatchCVENameFromList(srcCVEList []armotypes.VulnerabilityExceptionPolicy, CVEName string) []armotypes.VulnerabilityExceptionPolicy {
	var l []armotypes.VulnerabilityExceptionPolicy

	for i := range srcCVEList {
		for j := range srcCVEList[i].VulnerabilityPolicies {
			if srcCVEList[i].VulnerabilityPolicies[j].Name == CVEName {
				l = append(l, srcCVEList[i])
			}
		}
	}

	if len(l) > 0 {
		return l
	}
	return nil
}

func parseLayersPayload(target source.ImageMetadata) (map[string]containerscan.ESLayer, error) {
	layerMap := make(map[string]containerscan.ESLayer)
	if target.RawConfig == nil {
		return layerMap, nil
	}

	jsonConfig := &v1.ConfigFile{}
	valueConfig, _ := base64.StdEncoding.DecodeString(string(target.RawConfig))
	err := json.Unmarshal(valueConfig, jsonConfig)
	if err != nil {
		return nil, err
	}

	listLayers := make([]containerscan.ESLayer, 0)
	for i := range jsonConfig.History {

		if !jsonConfig.History[i].EmptyLayer {
			listLayers = append(listLayers, containerscan.ESLayer{LayerInfo: &containerscan.LayerInfo{
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

	return layerMap, nil
}

func convertToCommonContainerVulnerabilityResult(ctx context.Context, grypeDocument *models.Document, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) ([]containerscan.CommonContainerVulnerabilityResult, error) {
	var vulnerabilityResults []containerscan.CommonContainerVulnerabilityResult

	// retrieve timestamp from context
	timestamp, ok := ctx.Value(domain.TimestampKey).(int64)
	if !ok {
		return vulnerabilityResults, errors.New("no timestamp found in context")
	}
	// retrieve scanID from context
	scanID, ok := ctx.Value(domain.ScanIDKey).(string)
	if !ok {
		return vulnerabilityResults, errors.New("no scanID found in context")
	}
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return vulnerabilityResults, errors.New("no workload found in context")
	}

	if grypeDocument.Source != nil {
		// generate a map of child to parent
		parentLayerHash := ""
		parentLayer := map[string]string{
			dummyLayer: parentLayerHash,
		}
		target := grypeDocument.Source.Target.(source.ImageMetadata)
		for _, layer := range target.Layers {
			parentLayer[layer.Digest] = parentLayerHash
			parentLayerHash = layer.Digest
		}
		// iterate over all vulnerabilities
		for _, match := range grypeDocument.Matches {
			var isFixed int
			var version string
			var description string
			link := "https://nvd.nist.gov/vuln/detail/" + match.Vulnerability.ID
			if len(match.Vulnerability.Fix.Versions) != 0 {
				isFixed = 1
				version = match.Vulnerability.Fix.Versions[0]
			}
			if len(match.RelatedVulnerabilities) != 0 {
				description = match.RelatedVulnerabilities[0].Description
			}
			// create a vulnerability result for this vulnerability
			vulnerabilityResult := containerscan.CommonContainerVulnerabilityResult{
				IsLastScan:      1,
				WLID:            workload.Wlid,
				ContainerScanID: scanID,
				Layers:          []containerscan.ESLayer{},
				Timestamp:       timestamp,
				IsFixed:         isFixed,
				RelevantLinks: []string{
					link,
					match.Vulnerability.DataSource,
				},
				Vulnerability: containerscan.Vulnerability{
					Name:               match.Vulnerability.ID,
					ImageID:            workload.ImageHash,
					ImageTag:           workload.ImageTag,
					RelatedPackageName: match.Artifact.Name,
					PackageVersion:     match.Artifact.Version,
					Link:               link,
					Description:        description,
					Severity:           match.Vulnerability.Severity,
					SeverityScore:      containerscan.SeverityStr2Score[match.Vulnerability.Severity],
					Fixes: []containerscan.FixedIn{
						{
							Name:    match.Vulnerability.Fix.State,
							ImgTag:  workload.ImageTag,
							Version: version,
						},
					},
					ExceptionApplied: getCVEExceptionMatchCVENameFromList(vulnerabilityExceptionPolicyList, match.Vulnerability.ID),
					IsRelevant:       nil, // TODO add relevancy here?
				},
			}
			// add RCE information
			vulnerabilityResult.Categories.IsRCE = vulnerabilityResult.IsRCE()
			// add layer information
			// make sure we have at least one location
			if match.Artifact.Locations == nil || len(match.Artifact.Locations) < 1 {
				match.Artifact.Locations = []source.Coordinates{
					{
						FileSystemID: dummyLayer,
					},
				}
			}
			// iterate over locations
			for _, location := range match.Artifact.Locations {
				// create a layer
				layer := containerscan.ESLayer{
					LayerHash:       location.FileSystemID,
					ParentLayerHash: parentLayer[location.FileSystemID],
				}
				// add layer to vulnerability result
				vulnerabilityResult.Layers = append(vulnerabilityResult.Layers, layer)
			}

			vulnerabilityResults = append(vulnerabilityResults, vulnerabilityResult)
		}
		// parse layers from payload
		data, err := parseLayersPayload(target)
		if err != nil {
			return vulnerabilityResults, err
		}
		// fill extra layer information
		for i, v := range vulnerabilityResults {
			earlyLayer := ""
			for j, layer := range v.Layers {
				if layer.ParentLayerHash == earlyLayer {
					earlyLayer = layer.LayerHash
				}
				if l, ok := data[layer.LayerHash]; ok {
					if layer.LayerInfo == nil {
						vulnerabilityResults[i].Layers[j].LayerInfo = &containerscan.LayerInfo{}
					}
					vulnerabilityResults[i].Layers[j].CreatedBy = l.CreatedBy
					vulnerabilityResults[i].Layers[j].CreatedTime = l.CreatedTime
					vulnerabilityResults[i].Layers[j].LayerOrder = l.LayerOrder
				}
			}
			vulnerabilityResults[i].IntroducedInLayer = earlyLayer
		}
	}

	return vulnerabilityResults, nil
}
