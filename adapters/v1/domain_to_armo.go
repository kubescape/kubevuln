package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type Target struct {
	directoryMetadata *source.DirectoryMetadata
	imageMetadata     *source.ImageMetadata
}

func NewTargetFromSource(src *v1beta1.Source) (Target, error) {
	var target Target
	if src == nil {
		return target, fmt.Errorf("grype document source is nil")
	}

	switch src.Type {
	case "directory":
		// Try unmarshaling into DirectoryMetadata first
		var directoryMetadata source.DirectoryMetadata
		if err := json.Unmarshal(src.Target, &directoryMetadata); err == nil {
			target.directoryMetadata = &directoryMetadata
		} else {
			// Fallback: try unmarshaling as a raw string path
			var path string
			if err := json.Unmarshal(src.Target, &path); err != nil {
				return target, fmt.Errorf("failed to unmarshal directory target as either DirectoryMetadata or string: %w", err)
			}
			if filepath.IsAbs(path) {
				target.directoryMetadata = &source.DirectoryMetadata{Path: path}
			} else {
				return target, fmt.Errorf("expected a 'directory' to represent a valid path but got: %s", path)
			}
		}
	// defaults to image
	default:
		var imageMetadata source.ImageMetadata
		err := json.Unmarshal(src.Target, &imageMetadata)
		if err != nil {
			return target, err
		}
		target.imageMetadata = &imageMetadata
	}

	return target, nil
}

func (s *Target) IsImageTarget() bool {
	return s.imageMetadata != nil
}
func (s *Target) IsDirectoryTarget() bool {
	return s.directoryMetadata != nil
}

func (s *Target) GetImageMetadata() *source.ImageMetadata {
	return s.imageMetadata
}

func (s *Target) GetDirectoryMetadata() *source.DirectoryMetadata {
	return s.directoryMetadata
}

func DomainToArmo(ctx context.Context, grypeDocument v1beta1.GrypeDocument, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) ([]containerscan.CommonContainerVulnerabilityResult, error) {
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
		return vulnerabilityResults, domain.ErrCastingWorkload
	}

	if grypeDocument.Source != nil {
		// generate a map of child to parent
		parentLayerHash := ""
		parentLayer := map[string]string{
			dummyLayer: parentLayerHash,
		}

		target, err := NewTargetFromSource(grypeDocument.Source)
		if err != nil {
			return vulnerabilityResults, err
		}

		if target.IsImageTarget() {
			imageMetadata := target.GetImageMetadata()
			for _, layer := range imageMetadata.Layers {
				parentLayer[layer.Digest] = parentLayerHash
				parentLayerHash = layer.Digest
			}
		}

		// iterate over all vulnerabilities
		for _, m := range grypeDocument.Matches {
			var isFixed int
			var version string
			description := m.Vulnerability.Description
			link := linkToVuln(m.Vulnerability.ID)
			if len(m.Vulnerability.Fix.Versions) != 0 {
				isFixed = 1
				version = suggestedVersion(m.Artifact.Version, m.Vulnerability.Fix.Versions)
			} else {
				// also check CPE matches
				for _, detail := range m.MatchDetails {
					var found match.CPEResult
					err := json.Unmarshal(detail.Found, &found)
					if err == nil {
						// we assume that if a higher version is mentioned in the CPE, then it is fixed somewhere
						if strings.Contains(found.VersionConstraint, "<") {
							isFixed = 1
							version = "unknown"
							break
						}
					}
				}
			}
			if description == "" && len(m.RelatedVulnerabilities) > 0 {
				description = m.RelatedVulnerabilities[0].Description
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
					m.Vulnerability.DataSource,
				},
				Vulnerability: containerscan.Vulnerability{
					Name:               m.Vulnerability.ID,
					ImageID:            workload.ImageHash,
					ImageTag:           workload.ImageTagNormalized,
					RelatedPackageName: m.Artifact.Name,
					PackageVersion:     m.Artifact.Version,
					Link:               link,
					Description:        description,
					Severity:           m.Vulnerability.Severity,
					SeverityScore:      containerscan.SeverityStr2Score[m.Vulnerability.Severity],
					Fixes: []containerscan.FixedIn{
						{
							Name:    m.Vulnerability.Fix.State,
							ImgTag:  workload.ImageTagNormalized,
							Version: version,
						},
					},
					PackageType:      string(m.Artifact.Type),
					ExceptionApplied: getCVEExceptionMatchCVENameFromList(vulnerabilityExceptionPolicyList, m.Vulnerability.ID, isFixed == 1),
					IsRelevant:       nil, // TODO add relevancy here?
					Coordinates:      syftCoordinatesToCoordinates(m.Artifact.Locations),
				},
			}
			// add RCE information
			vulnerabilityResult.Categories.IsRCE = vulnerabilityResult.IsRCE()
			// add layer information
			// make sure we have at least one location
			if m.Artifact.Locations == nil || len(m.Artifact.Locations) < 1 {
				m.Artifact.Locations = []v1beta1.SyftCoordinates{
					{
						FileSystemID: dummyLayer,
					},
				}
			}
			// iterate over locations
			for _, location := range m.Artifact.Locations {
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
		if target.IsImageTarget() {
			imageMetadata := target.GetImageMetadata()
			// parse layers from payload
			data, err := parseLayersPayload(*imageMetadata)
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
	}

	return vulnerabilityResults, nil
}

func linkToVuln(id string) string {
	switch {
	case strings.HasPrefix("EUVD-", id):
		return "https://euvd.enisa.europa.eu/enisa/" + id
	case strings.HasPrefix("GHSA-", id):
		return "https://github.com/advisories/" + id
	default:
		return "https://nvd.nist.gov/vuln/detail/" + id
	}
}

func suggestedVersion(current string, versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	// compare with semver
	// if current is not a version, return the first version
	if c, err := semver.NewVersion(current); err == nil {
		for _, version := range versions {
			v, err := semver.NewVersion(version)
			if err == nil {
				if c.LessThan(v) {
					return version
				}
			}
		}
	}
	return versions[0]
}

func parseLayersPayload(target source.ImageMetadata) (map[string]containerscan.ESLayer, error) {
	layerMap := make(map[string]containerscan.ESLayer)
	if target.RawConfig == nil {
		return layerMap, nil
	}

	jsonConfig := &v1.ConfigFile{}
	err := json.Unmarshal(target.RawConfig, jsonConfig)
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

func syftCoordinatesToCoordinates(c []v1beta1.SyftCoordinates) []containerscan.Coordinates {
	var coordinates []containerscan.Coordinates
	for _, v := range c {
		coordinates = append(coordinates, containerscan.Coordinates{
			RealPath:     v.RealPath,
			FileSystemID: v.FileSystemID,
		})
	}
	return coordinates

}

func ParseImageManifest(grypeDocument *v1beta1.GrypeDocument) (*containerscan.ImageManifest, error) {
	if grypeDocument == nil || grypeDocument.Source == nil {
		return nil, fmt.Errorf("empty grype document")
	}

	var rawManifest source.ImageMetadata
	if err := json.Unmarshal(grypeDocument.Source.Target, &rawManifest); err != nil {
		return nil, err
	}

	var config v1.ConfigFile
	err := json.Unmarshal(rawManifest.RawConfig, &config)
	if err != nil {
		return nil, err
	}

	imageManifest := containerscan.ImageManifest{
		Architecture: config.Architecture,
		OS:           config.OS,
		Size:         rawManifest.Size,
		Layers:       []containerscan.ESLayer{},
	}

	layerIndex := 0
	for i, historyLayer := range config.History {
		layerInfo := containerscan.ESLayer{
			LayerInfo: &containerscan.LayerInfo{
				CreatedBy:   historyLayer.CreatedBy,
				CreatedTime: &historyLayer.Created.Time,
				LayerOrder:  i,
			},
		}
		if !historyLayer.EmptyLayer && layerIndex < len(rawManifest.Layers) {
			layerInfo.LayerHash = rawManifest.Layers[layerIndex].Digest
			layerInfo.Size = rawManifest.Layers[layerIndex].Size
			layerIndex++
		}
		imageManifest.Layers = append(imageManifest.Layers, layerInfo)
	}
	return &imageManifest, nil
}
