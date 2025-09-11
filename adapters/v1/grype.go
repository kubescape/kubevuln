package v1

import (
	"context"
	"os"
	"path"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/clio"
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
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel"
)

// GrypeAdapter implements CVEScanner from ports using Grype's API
type GrypeAdapter struct {
	lastDbUpdate       time.Time
	dbCloser           *db.Closer
	dbStatus           *db.Status
	store              *store.Store
	dbConfig           db.Config
	mu                 sync.RWMutex
	useDefaultMatchers bool
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure
// DB loading is done via readiness probes
func NewGrypeAdapter(listingURL string, useDefaultMatchers bool) *GrypeAdapter {
	g := &GrypeAdapter{
		dbConfig: db.Config{
			DBRootDir:  path.Join(xdg.CacheHome, "grype", "db"),
			ListingURL: listingURL,
		},
		useDefaultMatchers: useDefaultMatchers,
	}
	return g
}

func NewGrypeAdapterFixedDB() *GrypeAdapter {
	g := &GrypeAdapter{
		dbConfig: db.Config{
			DBRootDir:  path.Join(xdg.CacheHome, "grype-light", "db"),
			ListingURL: "http://localhost:8000/listing.json",
		},
	}
	return g
}

// DBVersion returns the vulnerabilities DB checksum which is used to tag CVE manifests
func (g *GrypeAdapter) DBVersion(context.Context) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.dbStatus.Checksum
}

// Ready returns the status of the vulnerabilities DB
func (g *GrypeAdapter) Ready(ctx context.Context) bool {
	// DB update is in progress
	if !g.mu.TryRLock() {
		// FIXME this gets stuck forever if the db update times out
		return false
	}
	g.mu.RUnlock() // because TryRLock doesn't unlock
	// DB is not initialized or needs to be updated
	now := time.Now()
	if g.dbStatus == nil || now.Sub(g.lastDbUpdate) > 24*time.Hour {
		g.mu.Lock()
		defer g.mu.Unlock()
		ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.UpdateDB")
		defer span.End()
		logger.L().Info("updating grype DB",
			helpers.String("listingURL", g.dbConfig.ListingURL))
		var err error
		g.store, g.dbStatus, g.dbCloser, err = grype.LoadVulnerabilityDB(g.dbConfig, true)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to update grype DB", helpers.Error(err))
			err := tools.DeleteContents(g.dbConfig.DBRootDir)
			logger.L().Debug("cleaned up cache", helpers.Error(err),
				helpers.String("DBRootDir", g.dbConfig.DBRootDir))
			logger.L().Info("restarting to release previous grype DB")
			os.Exit(0)
		}
		g.lastDbUpdate = now
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

	if g.dbStatus == nil {
		return domain.CVEManifest{}, domain.ErrInitVulnDB
	}

	logger.L().Debug("decoding SBOM",
		helpers.String("name", sbom.Name))
	s, err := domainToSyft(*sbom.Content)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("reading packages from SBOM", helpers.String("name", sbom.Name))
	packages := pkg.FromCollection(s.Artifacts.Packages, pkg.SynthesisConfig{})

	pkgContext := pkg.Context{
		Source: &s.Source,
		Distro: s.Artifacts.LinuxDistribution,
	}
	vulnMatcher := grype.VulnerabilityMatcher{
		Store:          *g.store,
		Matchers:       getMatchers(g.useDefaultMatchers),
		NormalizeByCVE: true,
	}

	logger.L().Debug("finding vulnerabilities",
		helpers.String("name", sbom.Name))
	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("compiling results",
		helpers.String("name", sbom.Name))
	doc, err := models.NewDocument(clio.Identification{}, packages, pkgContext, *remainingMatches, ignoredMatches, g.store, nil, g.dbStatus)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("converting results to common format",
		helpers.String("name", sbom.Name))
	vulnerabilityResults, err := grypeToDomain(doc)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	// retrieve scanID from context and add it to the annotations
	scanID, _ := ctx.Value(domain.ScanIDKey{}).(string)
	sbom.Annotations[helpersv1.ScanIdMetadataKey] = scanID

	logger.L().Debug("returning CVE manifest",
		helpers.String("name", sbom.Name),
		helpers.Int("vulnerabilities", len(vulnerabilityResults.Matches)))
	return domain.CVEManifest{
		Name:               sbom.Name,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  g.Version(),
		CVEDBVersion:       g.DBVersion(ctx),
		Annotations:        sbom.Annotations,
		Labels:             sbom.Labels,
		Content:            vulnerabilityResults,
	}, nil
}

func getMatchers(useDefaultMatchers bool) []matcher.Matcher {
	if useDefaultMatchers {
		return matcher.NewDefaultMatchers(defaultMatcherConfig())
	}
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

func defaultMatcherConfig() matcher.Config {
	return matcher.Config{
		Java: java.MatcherConfig{
			ExternalSearchConfig: java.ExternalSearchConfig{MavenBaseURL: "https://search.maven.org/solrsearch/select"},
			UseCPEs:              false,
		},
		Ruby:       ruby.MatcherConfig{UseCPEs: false},
		Python:     python.MatcherConfig{UseCPEs: false},
		Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
		Javascript: javascript.MatcherConfig{UseCPEs: false},
		Golang: golang.MatcherConfig{
			UseCPEs:                                false,
			AlwaysUseCPEForStdlib:                  true,
			AllowMainModulePseudoVersionComparison: false,
		},
		Stock: stock.MatcherConfig{UseCPEs: true},
	}
}

// Version returns Grype's version which is used to tag CVE manifests
func (g *GrypeAdapter) Version() string {
	v := tools.PackageVersion("github.com/anchore/grype")
	if g.useDefaultMatchers {
		v += "-default-matchers"
	}
	return v
}
