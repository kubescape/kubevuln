package v1

import (
	"bytes"
	"context"
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
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/syft/syft"
	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
	v2 "github.com/armosec/cluster-container-scanner-api/containerscan/v2"
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

func scanResultReport() *v2.ScanResultReport {
	return &v2.ScanResultReport{
		Designators: armotypes.PortalDesignator{
			DesignatorType: "",
			WLID:           "",
			WildWLID:       "",
			SID:            "",
			Attributes:     map[string]string{},
		},
		Timestamp:       0,
		ContainerScanID: "",
		Vulnerabilities: []v2.CommonContainerVulnerabilityResult{
			{
				Designators: armotypes.PortalDesignator{
					DesignatorType: "",
					WLID:           "",
					WildWLID:       "",
					SID:            "",
					Attributes:     map[string]string{},
				},
				Context: []armotypes.ArmoContext{
					{
						Attribute: "",
						Value:     "",
						Source:    "",
					},
				},
				WLID:              "",
				ContainerScanID:   "",
				Layers:            []containerscan.ESLayer{},
				LayersNested:      []containerscan.ESLayer{},
				Timestamp:         0,
				IsLastScan:        0,
				IsFixed:           0,
				IntroducedInLayer: "",
				RelevantLinks:     []string{},
				RelatedExceptions: []armotypes.VulnerabilityExceptionPolicy{
					{
						PortalBase: armotypes.PortalBase{
							GUID:        "",
							Name:        "",
							Attributes:  map[string]interface{}{},
							UpdatedTime: "",
						},
						PolicyType:            "",
						CreationTime:          "",
						Actions:               nil,
						Designatores:          nil,
						VulnerabilityPolicies: nil,
					},
				},
				Vulnerability: v2.Vulnerability{},
			},
		},
		Summary: &v2.CommonContainerScanSummaryResult{
			SeverityStats: containerscan.SeverityStats{
				Severity:                     "",
				TotalCount:                   0,
				RCEFixCount:                  0,
				FixAvailableOfTotalCount:     0,
				RelevantCount:                0,
				FixAvailableForRelevantCount: 0,
				RCECount:                     0,
				UrgentCount:                  0,
				NeglectedCount:               0,
				HealthStatus:                 "",
			},
			Designators: armotypes.PortalDesignator{
				DesignatorType: "",
				WLID:           "",
				WildWLID:       "",
				SID:            "",
				Attributes:     nil,
			},
			Context:                       []armotypes.ArmoContext{},
			JobIDs:                        []string{},
			CustomerGUID:                  "",
			ContainerScanID:               "",
			Timestamp:                     0,
			WLID:                          "",
			ImageID:                       "",
			ImageTag:                      "",
			ClusterName:                   "",
			Namespace:                     "",
			ContainerName:                 "",
			PackagesName:                  []string{},
			ListOfDangerousArtifcats:      []string{},
			Status:                        "",
			Registry:                      "",
			VersionImage:                  "",
			SeveritiesStats:               []containerscan.SeverityStats{},
			ExcludedSeveritiesStats:       []containerscan.SeverityStats{},
			Version:                       "",
			Vulnerabilities:               []containerscan.ShortVulnerabilityResult{},
			ImageSignatureValid:           false,
			ImageHasSignature:             false,
			ImageSignatureValidationError: "",
		},
		PaginationInfo: wssc.PaginationMarks{
			ReportNumber: 0,
			IsLastReport: false,
		},
		IsRelevancy: false,
	}
}

// ScanSBOM generates a CVE manifest by scanning an SBOM
func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
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

	// TODO get CVE exceptions from platform
	//var exceptions []armotypes.VulnerabilityExceptionPolicy

	// generate JSON
	presenterConfig := models.PresenterConfig{
		Matches:          *remainingMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: g.store,
		SBOM:             s,
		AppConfig:        nil,
		DBStatus:         g.dbStatus,
	}
	presenter := json.NewPresenter(presenterConfig)
	var buf bytes.Buffer
	err = presenter.Present(&buf)
	if err != nil {
		return domain.CVEManifest{}, err
	}
	return domain.CVEManifest{
		ImageID:            sbom.ImageID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  g.Version(),
		CVEDBVersion:       g.DBVersion(),
		Content:            scanResultReport(),
	}, nil
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
