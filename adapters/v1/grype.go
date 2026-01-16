package v1

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
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
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel"
)

// GrypeAdapter implements CVEScanner from ports using Grype's API
type GrypeAdapter struct {
	lastDbUpdate       time.Time
	dbStatus           *vulnerability.ProviderStatus
	store              vulnerability.Provider
	distCfg            distribution.Config
	installCfg         installation.Config
	mu                 sync.RWMutex
	useDefaultMatchers bool
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure
// DB loading is done via readiness probes
func NewGrypeAdapter(listingURL string, useDefaultMatchers bool) *GrypeAdapter {
	g := &GrypeAdapter{
		distCfg: distribution.Config{
			LatestURL: listingURL,
		},
		installCfg: installation.Config{
			DBRootDir: path.Join(xdg.CacheHome, "grype", "db"),
		},
		useDefaultMatchers: useDefaultMatchers,
	}
	return g
}

func startGrypeOfflineDBContainer(ctx context.Context) (port string, terminate func(), err error) {
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/kubescape/grype-offline-db:v6-ci-only",
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForExposedPort(),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", nil, err
	}

	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		return "", nil, err
	}

	terminate = func() {
		_ = container.Terminate(ctx)
	}
	return mappedPort.Port(), terminate, nil
}

func NewGrypeAdapterFixedDB() (*GrypeAdapter, func(), error) {
	// start grype-offline-db container
	port, terminate, err := startGrypeOfflineDBContainer(context.Background())
	if err != nil {
		return nil, nil, err
	}
	g := &GrypeAdapter{
		distCfg: distribution.Config{
			LatestURL: fmt.Sprintf("http://localhost:%s/databases", port),
		},
		installCfg: installation.Config{
			DBRootDir: path.Join(xdg.CacheHome, "grype-offline", "db"),
		},
	}
	return g, terminate, nil
}

func (g *GrypeAdapter) dbVersionLocked() string {
	if g.dbStatus == nil {
		return ""
	}
	parts := strings.Split(g.dbStatus.From, "%3A")
	return parts[len(parts)-1]
}

// DBVersion returns the vulnerabilities DB checksum which is used to tag CVE manifests
func (g *GrypeAdapter) DBVersion(context.Context) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.dbVersionLocked()
}

// Ready returns the status of the vulnerabilities DB
func (g *GrypeAdapter) Ready(ctx context.Context) bool {
	// DB update is in progress
	if !g.mu.TryRLock() {
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
			helpers.String("listingURL", g.distCfg.LatestURL))

		// Create a context with timeout to prevent stuck updates
		// 15 minutes allows for slow network connections while still catching truly stuck downloads
		updateCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()

		// Track if we have an existing DB to fall back on
		hasExistingDB := g.dbStatus != nil

		// Run the DB update in a goroutine to respect the timeout
		type updateResult struct {
			store    vulnerability.Provider
			dbStatus *vulnerability.ProviderStatus
			err      error
		}
		// Buffered channel (size 1) prevents goroutine from blocking if timeout occurs
		// The goroutine will complete in background but won't leak since it will successfully send
		resultCh := make(chan updateResult, 1)

		go func() {
			// Note: grype.LoadVulnerabilityDB does not accept context, so the goroutine
			// will continue to completion even if timeout occurs. The buffered channel
			// ensures the goroutine can complete without blocking.
			store, dbStatus, err := grype.LoadVulnerabilityDB(g.distCfg, g.installCfg, true)
			resultCh <- updateResult{store: store, dbStatus: dbStatus, err: err}
		}()

		select {
		case result := <-resultCh:
			if result.err != nil {
				logger.L().Ctx(ctx).Error("failed to update grype DB", helpers.Error(result.err))
				err := tools.DeleteContents(g.installCfg.DBRootDir)
				logger.L().Debug("cleaned up cache", helpers.Error(err),
					helpers.String("DBRootDir", g.installCfg.DBRootDir))
				logger.L().Info("restarting to release previous grype DB")
				os.Exit(0)
			}
			g.store = result.store
			g.dbStatus = result.dbStatus
			g.lastDbUpdate = now
			logger.L().Info("grype DB updated")
			return true
		case <-updateCtx.Done():
			if hasExistingDB {
				// We have an existing DB, keep using it instead of crashing
				// This prevents crashloop in case of slow but functional network
				logger.L().Ctx(ctx).Warning("grype DB update timed out after 15 minutes, continuing with existing DB",
					helpers.String("existingDBVersion", g.dbVersionLocked()))
				// Update lastDbUpdate to prevent immediate retry, will retry in next 24h cycle
				g.lastDbUpdate = now
				return true
			} else {
				// No existing DB to fall back on, must restart
				logger.L().Ctx(ctx).Error("grype DB initial download timed out after 15 minutes")
				err := tools.DeleteContents(g.installCfg.DBRootDir)
				logger.L().Debug("cleaned up cache after timeout", helpers.Error(err),
					helpers.String("DBRootDir", g.installCfg.DBRootDir))
				logger.L().Info("restarting pod due to grype DB initial download timeout")
				os.Exit(0)
			}
		}
	}

	return g.dbStatus.Error == nil
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

	dist := distro.FromRelease(s.Artifacts.LinuxDistribution, distro.DefaultFixChannels())

	logger.L().Debug("reading packages from SBOM", helpers.String("name", sbom.Name))
	packages := pkg.FromCollection(s.Artifacts.Packages, pkg.SynthesisConfig{
		GenerateMissingCPEs: false,
		Distro: pkg.DistroConfig{
			Override:    dist,
			FixChannels: distro.DefaultFixChannels(),
		}})

	pkgContext := pkg.Context{
		Source: &s.Source,
		Distro: dist,
	}
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: g.store,
		Matchers:              getMatchers(g.useDefaultMatchers),
		NormalizeByCVE:        true,
	}

	logger.L().Debug("finding vulnerabilities",
		helpers.String("name", sbom.Name))
	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return domain.CVEManifest{}, err
	}

	logger.L().Debug("compiling results",
		helpers.String("name", sbom.Name))
	doc, err := models.NewDocument(clio.Identification{}, packages, pkgContext, *remainingMatches, ignoredMatches, g.store, nil, g.dbStatus, models.DefaultSortStrategy, false)
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
	if sbom.Annotations == nil {
		sbom.Annotations = make(map[string]string)
	}
	sbom.Annotations[helpersv1.ScanIdMetadataKey] = scanID

	logger.L().Debug("returning CVE manifest",
		helpers.String("name", sbom.Name),
		helpers.Int("vulnerabilities", len(vulnerabilityResults.Matches)))
	return domain.CVEManifest{
		Name:               sbom.Name,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  g.Version(),
		CVEDBVersion:       g.dbVersionLocked(),
		Annotations:        sbom.Annotations,
		Labels:             sbom.Labels,
		Content:            vulnerabilityResults,
	}, nil
}

func getMatchers(useDefaultMatchers bool) []match.Matcher {
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
