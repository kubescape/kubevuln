package v1

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func domainToArmo(ctx context.Context, grypeDocument v1beta1.GrypeDocument, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) ([]containerscan.CommonContainerVulnerabilityResult, error) {
	var vulnerabilityResults []containerscan.CommonContainerVulnerabilityResult

	// retrieve timestamp from context
	timestamp, ok := ctx.Value(domain.TimestampKey{}).(int64)
	if !ok {
		return vulnerabilityResults, domain.ErrMissingTimestamp
	}
	// retrieve scanID from context
	scanID, ok := ctx.Value(domain.ScanIDKey{}).(string)
	if !ok {
		return vulnerabilityResults, domain.ErrMissingScanID
	}
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return vulnerabilityResults, domain.ErrMissingWorkload
	}

	if grypeDocument.Source != nil {
		// generate a map of child to parent
		parentLayerHash := ""
		parentLayer := map[string]string{
			dummyLayer: parentLayerHash,
		}
		var target source.ImageMetadata
		err := json.Unmarshal(grypeDocument.Source.Target, &target)
		if err != nil {
			return vulnerabilityResults, err
		}
		for _, layer := range target.Layers {
			parentLayer[layer.Digest] = parentLayerHash
			parentLayerHash = layer.Digest
		}
		// iterate over all vulnerabilities
		for _, match := range grypeDocument.Matches {
			var isFixed int
			var version string
			description := match.Vulnerability.Description
			link := "https://nvd.nist.gov/vuln/detail/" + match.Vulnerability.ID
			if len(match.Vulnerability.Fix.Versions) != 0 {
				isFixed = 1
				version = match.Vulnerability.Fix.Versions[0]
			}
			if description == "" && len(match.RelatedVulnerabilities) > 0 {
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
					ExceptionApplied: getCVEExceptionMatchCVENameFromList(vulnerabilityExceptionPolicyList, match.Vulnerability.ID, isFixed == 1),
					IsRelevant:       nil, // TODO add relevancy here?
				},
			}
			// add RCE information
			vulnerabilityResult.Categories.IsRCE = vulnerabilityResult.IsRCE()
			// add layer information
			// make sure we have at least one location
			if match.Artifact.Locations == nil || len(match.Artifact.Locations) < 1 {
				match.Artifact.Locations = []v1beta1.SyftCoordinates{
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

			isRelevant := vulnerabilityResult.GetIsRelevant()
			if isRelevant != nil {
				if *isRelevant {
					vulnerabilityResult.SetRelevantLabel(containerscan.RelevantLabelYes)
				} else {
					vulnerabilityResult.SetRelevantLabel(containerscan.RelevantLabelNo)
				}
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
