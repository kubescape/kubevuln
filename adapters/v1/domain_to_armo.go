package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
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
		// ...and one of layer to its position in the image, so the earliest layer a package
		// appears in can be picked directly rather than by walking the chain from the root.
		layerPosition := map[string]int{}

		target, err := NewTargetFromSource(grypeDocument.Source)
		if err != nil {
			return vulnerabilityResults, err
		}

		if target.IsImageTarget() {
			imageMetadata := target.GetImageMetadata()
			for i, layer := range imageMetadata.Layers {
				parentLayer[layer.Digest] = parentLayerHash
				parentLayerHash = layer.Digest
				layerPosition[layer.Digest] = i
			}
		}

		// iterate over all vulnerabilities
		for _, m := range grypeDocument.Matches {
			var isFixed int
			description := m.Vulnerability.Description
			link := linkToVuln(m.Vulnerability.ID)
			fixed, version := hasKnownFix(m)
			if fixed {
				isFixed = 1
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
					ExceptionApplied: scopedToSubcomponent(getCVEExceptionMatchCVENameFromList(vulnerabilityExceptionPolicyList, m.Vulnerability.ID, isFixed == 1), m.Artifact.PURL),
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
				// The package is introduced by the earliest layer it appears in. This used to
				// walk the parent chain from "", which meant it only ever resolved for a
				// package present in the image's first layer: for anything added by a later
				// layer no element could start the chain, and the result stayed empty.
				earlyLayer := ""
				earlyPosition := 0
				for j, layer := range v.Layers {
					if position, ok := layerPosition[layer.LayerHash]; ok && (earlyLayer == "" || position < earlyPosition) {
						earlyLayer, earlyPosition = layer.LayerHash, position
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
				if earlyLayer == "" && len(v.Layers) > 0 {
					// No layer of this package is one of the image's own, which is the case
					// for a match with no locations: it is given the placeholder layer above.
					earlyLayer = v.Layers[0].LayerHash
				}
				vulnerabilityResults[i].IntroducedInLayer = earlyLayer
			}
		}
	}

	return vulnerabilityResults, nil
}

func linkToVuln(id string) string {
	switch {
	case strings.HasPrefix(id, "EUVD-"):
		return "https://euvd.enisa.europa.eu/enisa/" + id

	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id

	case strings.HasPrefix(id, "RHSA-"):
		return "https://access.redhat.com/errata/" + id

	case strings.HasPrefix(id, "USN-"):
		return "https://ubuntu.com/security/notices/" + id + "/"

	case strings.HasPrefix(id, "DSA-"):
		return "https://security-tracker.debian.org/tracker/" + id

	case strings.HasPrefix(id, "ELSA-"):
		return "https://linux.oracle.com/errata/" + id + ".html"

	case strings.HasPrefix(id, "RLSA-"):
		return "https://errata.rockylinux.org/" + id

	case strings.HasPrefix(id, "ALAS2023-"):
		return "https://alas.aws.amazon.com/AL2023/ALAS-" +
			strings.TrimPrefix(id, "ALAS2023-") + ".html"

	case strings.HasPrefix(id, "ALAS2-"):
		return "https://alas.aws.amazon.com/AL2/ALAS-" +
			strings.TrimPrefix(id, "ALAS2-") + ".html"

	case strings.HasPrefix(id, "ALAS-"):
		return "https://alas.aws.amazon.com/" + id + ".html"

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

	// LayerOrder counts real, layer-producing history entries only, matching
	// parseLayersPayload's indexing (which builds the layerMap DomainToArmo attaches to
	// each vulnerability). History also contains metadata-only entries (ENV, LABEL, CMD,
	// etc.) that don't produce a layer; counting those too, as the raw loop index would,
	// gives every real layer a different LayerOrder here than in the vulnerability report
	// for the same layer hash, breaking any lookup that correlates the two by LayerOrder.
	layerIndex := 0
	for _, historyLayer := range config.History {
		layerInfo := containerscan.ESLayer{
			LayerInfo: &containerscan.LayerInfo{
				CreatedBy:   historyLayer.CreatedBy,
				CreatedTime: &historyLayer.Created.Time,
				LayerOrder:  layerIndex,
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
