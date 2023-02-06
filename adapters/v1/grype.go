package v1

import (
	"bytes"
	"context"
	"sync"

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
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type GrypeAdapter struct {
	dbCloser *db.Closer
	dbConfig db.Config
	dbStatus *db.Status
	mu       sync.RWMutex
	store    *store.Store
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

func NewGrypeAdapter(ctx context.Context) (*GrypeAdapter, error) {
	dbConfig := db.Config{
		DBRootDir:  "grypedb",
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
	}
	g := &GrypeAdapter{
		dbConfig: dbConfig,
	}
	err := g.UpdateDB(ctx)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (g *GrypeAdapter) CreateRelevantCVE(ctx context.Context, cve, cvep domain.CVE) (domain.CVE, error) {
	// TODO implement me
	panic("implement me")
}

func (g *GrypeAdapter) DBVersion() string {
	return g.dbStatus.Checksum
}

func (g *GrypeAdapter) Ready() bool {
	return g.dbStatus.Err != nil
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

func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVE, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ctx, span := otel.Tracer("").Start(ctx, "ScanSBOM")
	defer span.End()
	s, _, err := syft.Decode(bytes.NewReader(sbom.Content))
	if err != nil {
		return domain.CVE{}, err
	}
	packages := pkg.FromCatalog(s.Artifacts.PackageCatalog, pkg.SynthesisConfig{})
	if err != nil {
		return domain.CVE{}, err
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
		return domain.CVE{}, err
	}
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
		return domain.CVE{}, err
	}
	return domain.CVE{
		ImageID:            sbom.ImageID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  g.Version(),
		CVEDBVersion:       g.DBVersion(),
		Content:            buf.Bytes(),
	}, nil
}

func (g *GrypeAdapter) UpdateDB(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx, span := otel.Tracer("").Start(ctx, "UpdateDB")
	defer span.End()
	var err error
	g.store, g.dbStatus, g.dbCloser, err = grype.LoadVulnerabilityDB(g.dbConfig, true)
	return err
}

func (g *GrypeAdapter) Version() string {
	// TODO implement me
	return "TODO"
}
