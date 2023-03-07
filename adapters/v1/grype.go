package v1

import (
	"bytes"
	"context"
	"path"
	"sync"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/syft/syft"
	"github.com/kubescape/go-logger"
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
func (g *GrypeAdapter) DBVersion(ctx context.Context) string {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.DBVersion")
	defer span.End()
	return g.dbStatus.Checksum
}

// Ready returns the status of the vulnerabilities DB
func (g *GrypeAdapter) Ready(ctx context.Context) bool {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.Ready")
	defer span.End()
	return g.dbStatus.Err == nil
}

const dummyLayer = "generatedlayer"

// ScanSBOM generates a CVE manifest by scanning an SBOM
func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM, exceptions domain.CVEExceptions) (domain.CVEManifest, error) {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.ScanSBOM")
	defer span.End()

	g.mu.RLock()
	defer g.mu.RUnlock()

	logger.L().Debug("decoding SBOM")
	s, _, err := syft.Decode(bytes.NewReader(sbom.Content))
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("reading packages from SBOM")
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

	logger.L().Debug("finding vulnerabilities")
	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("compiling results")
	doc, err := models.NewDocument(packages, pkgContext, *remainingMatches, ignoredMatches, g.store, nil, g.dbStatus)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("converting results to common format")
	vulnerabilityResults, err := convertToCommonContainerVulnerabilityResult(ctx, &doc, exceptions)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("returning CVE manifest")
	return *domain.NewCVEManifest(
		sbom.ImageID,
		sbom.SBOMCreatorVersion,
		g.Version(ctx),
		g.DBVersion(ctx),
		vulnerabilityResults,
	), nil
}

// UpdateDB updates the vulnerabilities DB, a RWMutex ensures this process doesn't interfere with scans
func (g *GrypeAdapter) UpdateDB(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.UpdateDB")
	defer span.End()

	g.mu.Lock()
	defer g.mu.Unlock()

	var err error
	g.store, g.dbStatus, g.dbCloser, err = grype.LoadVulnerabilityDB(g.dbConfig, true)
	return err
}

// Version returns Grype's version which is used to tag CVE manifests
func (g *GrypeAdapter) Version(ctx context.Context) string {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.Ready")
	defer span.End()
	return tools.PackageVersion("github.com/anchore/grype")
}
