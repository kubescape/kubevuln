package v1

import (
	"context"
	"path"
	"sync"
	"time"

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
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel"
)

// GrypeAdapter implements CVEScanner from ports using Grype's API
type GrypeAdapter struct {
	mu       sync.RWMutex
	dbCloser *db.Closer
	dbStatus *db.Status
	store    *store.Store
	dbConfig db.Config
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure
// DB loading is done via readiness probes
func NewGrypeAdapter() *GrypeAdapter {
	dbConfig := db.Config{
		DBRootDir:  path.Join(xdg.CacheHome, "grype", "db"),
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
	}
	g := &GrypeAdapter{
		dbConfig: dbConfig,
	}
	return g
}

// DBVersion returns the vulnerabilities DB checksum which is used to tag CVE manifests
func (g *GrypeAdapter) DBVersion(ctx context.Context) string {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.DBVersion")
	defer span.End()

	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.dbStatus.Checksum
}

// Ready returns the status of the vulnerabilities DB
func (g *GrypeAdapter) Ready(ctx context.Context) bool {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.Ready")
	defer span.End()

	// DB update is in progress
	if !g.mu.TryRLock() {
		return false
	}
	g.mu.RUnlock() // because TryRLock doesn't unlock
	// DB is not initialized or needs to be updated
	now := time.Now()
	if g.dbStatus == nil || now.Sub(g.dbStatus.Built) > 24*time.Hour {
		g.mu.Lock()
		defer g.mu.Unlock()
		logger.L().Info("updating grype DB")
		var err error
		g.store, g.dbStatus, g.dbCloser, err = grype.LoadVulnerabilityDB(g.dbConfig, true)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to update grype DB", helpers.Error(err))
			return false
		}
		logger.L().Info("grype DB updated")
		return true
	}

	return g.dbStatus.Err == nil
}

const dummyLayer = "generatedlayer"

// ScanSBOM generates a CVE manifest by scanning an SBOM
func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.ScanSBOM")
	defer span.End()

	g.mu.RLock()
	defer g.mu.RUnlock()

	logger.L().Debug("decoding SBOM", helpers.String("imageID", sbom.ID))
	s, err := domainToSyft(*sbom.Content)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("reading packages from SBOM", helpers.String("imageID", sbom.ID))
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

	logger.L().Debug("finding vulnerabilities", helpers.String("imageID", sbom.ID))
	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("compiling results", helpers.String("imageID", sbom.ID))
	doc, err := models.NewDocument(packages, pkgContext, *remainingMatches, ignoredMatches, g.store, nil, g.dbStatus)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("converting results to common format", helpers.String("imageID", sbom.ID))
	vulnerabilityResults, err := grypeToDomain(doc)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("returning CVE manifest", helpers.String("imageID", sbom.ID))
	return domain.CVEManifest{
		ImageID:            sbom.ID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  g.Version(ctx),
		CVEDBVersion:       g.DBVersion(ctx),
		Content:            vulnerabilityResults,
	}, nil
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

// Version returns Grype's version which is used to tag CVE manifests
func (g *GrypeAdapter) Version(ctx context.Context) string {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.Ready")
	defer span.End()
	return tools.PackageVersion("github.com/anchore/grype")
}
