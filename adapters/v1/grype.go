package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path"
	"sync"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
	containerTypes "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel"
)

// GrypeAdapter implements CVEScanner from ports using Grype's API
type GrypeAdapter struct {
	dbCloser *db.Closer
	dbConfig db.Config
	dbStatus *db.Status
	mu       sync.RWMutex
	store    *store.Store
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure and loads the vulnerability DB
// by calling UpdateDB which will eventually update its definitions
// it can fail if the DB isn't initialized properly
func NewGrypeAdapter(ctx context.Context) (*GrypeAdapter, error) {
	dbConfig := db.Config{
		DBRootDir:  path.Join(xdg.CacheHome, "grype", "db"),
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
	}
	g := &GrypeAdapter{
		dbConfig: dbConfig,
	}
	err := g.UpdateDB(ctx) // TODO make it injectable
	if err != nil {
		return nil, err
	}
	return g, nil
}

// CreateRelevantCVE creates a relevant CVE combining CVE and CVE' vulnerabilities
func (g *GrypeAdapter) CreateRelevantCVE(ctx context.Context, cve, cvep domain.CVEManifest) (domain.CVEManifest, error) {
	// TODO implement me
	panic("implement me")
}

// DBVersion returns the vulnerabilities DB checksum which is used to tag CVE manifests
func (g *GrypeAdapter) DBVersion() string {
	return g.dbStatus.Checksum
}

// Ready returns the status of the vulnerabilities DB
func (g *GrypeAdapter) Ready() bool {
	return g.dbStatus.Err == nil
}

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

func parseLayersPayload(target source.ImageMetadata) (map[string]cs.ESLayer, error) {
	layerMap := make(map[string]cs.ESLayer)
	if target.RawConfig == nil {
		return layerMap, nil
	}

	jsonConfig := &containerTypes.ConfigFile{}
	valueConfig, _ := base64.StdEncoding.DecodeString(string(target.RawConfig))
	err := json.Unmarshal(valueConfig, jsonConfig)
	if err != nil {
		return nil, err
	}

	listLayers := make([]cs.ESLayer, 0)
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

	return layerMap, nil
}

const dummyLayer = "generatedlayer"

func convertToCommonContainerVulnerabilityResult(ctx context.Context, grypeDocument *models.Document, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) ([]cs.CommonContainerVulnerabilityResult, error) {
	var vulnerabilityResults []cs.CommonContainerVulnerabilityResult

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
			vulnerabilityResult := cs.CommonContainerVulnerabilityResult{
				IsLastScan:      1,
				WLID:            workload.Wlid,
				ContainerScanID: scanID,
				Layers:          []cs.ESLayer{},
				Timestamp:       timestamp,
				IsFixed:         isFixed,
				RelevantLinks: []string{
					link,
					match.Vulnerability.DataSource,
				},
				Vulnerability: cs.Vulnerability{
					Name:               match.Vulnerability.ID,
					ImageID:            workload.ImageHash,
					ImageTag:           workload.ImageTag,
					RelatedPackageName: match.Artifact.Name,
					PackageVersion:     match.Artifact.Version,
					Link:               link,
					Description:        description,
					Severity:           match.Vulnerability.Severity,
					SeverityScore:      cs.SeverityStr2Score[match.Vulnerability.Severity],
					Fixes: []cs.FixedIn{
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
				layer := cs.ESLayer{
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
						vulnerabilityResults[i].Layers[j].LayerInfo = &cs.LayerInfo{}
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

// ScanSBOM generates a CVE manifest by scanning an SBOM
func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM, exceptions domain.CVEExceptions) (domain.CVEManifest, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ctx, span := otel.Tracer("").Start(ctx, "ScanSBOM")
	defer span.End()

	s, _, err := syft.Decode(bytes.NewReader(sbom.Content))
	if err != nil {
		return domain.CVEManifest{}, err
	}

	packages := pkg.FromCatalog(s.Artifacts.PackageCatalog, pkg.SynthesisConfig{})
	if err != nil {
		return domain.CVEManifest{}, err
	}
	pkgContext := pkg.Context{
		Source: &s.Source,
		Distro: s.Artifacts.LinuxDistribution,
	}
	vulnMatcher := grype.VulnerabilityMatcher{
		Store:    *g.store,
		Matchers: getMatchers(),
	}

	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	doc, err := models.NewDocument(packages, pkgContext, *remainingMatches, ignoredMatches, g.store, nil, g.dbStatus)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	vulnerabilityResults, err := convertToCommonContainerVulnerabilityResult(ctx, &doc, exceptions)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	return *domain.NewCVEManifest(
		sbom.ImageID,
		sbom.SBOMCreatorVersion,
		g.Version(),
		g.DBVersion(),
		vulnerabilityResults,
	), nil
}

// UpdateDB updates the vulnerabilities DB, a RWMutex ensures this process doesn't interfere with scans
func (g *GrypeAdapter) UpdateDB(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	ctx, span := otel.Tracer("").Start(ctx, "UpdateDB")
	defer span.End()

	var err error
	g.store, g.dbStatus, g.dbCloser, err = grype.LoadVulnerabilityDB(g.dbConfig, true)
	return err
}

// Version returns Grype's version which is used to tag CVE manifests
func (g *GrypeAdapter) Version() string {
	return tools.PackageVersion("github.com/anchore/grype")
}
