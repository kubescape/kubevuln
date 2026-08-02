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
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel"
)

// Observability annotation keys for CVE manifests. They follow the same
// kubescape.io/<kebab> convention as the shared keys in k8s-interface, but are
// kubevuln-local since they describe a kubevuln scanning decision.
const (
	// CVEMatchingModeMetadataKey records the configured matching mode (off/on/adaptive).
	CVEMatchingModeMetadataKey = "kubescape.io/cve-matching-mode"
	// VendorTrustedMatchMetadataKey records the trusted vendor distro when adaptive
	// mode downgraded a scan to that vendor's authoritative feed.
	VendorTrustedMatchMetadataKey = "kubescape.io/vendor-trusted-match"
)

type loadDBFunc func(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error)

func defaultLoadDB(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	return grype.LoadVulnerabilityDB(distCfg, installCfg, true)
}

// GrypeAdapter implements CVEScanner from ports using Grype's API
type GrypeAdapter struct {
	lastDbUpdate   time.Time
	dbStatus       *vulnerability.ProviderStatus
	store          vulnerability.Provider
	distCfg        distribution.Config
	installCfg     installation.Config
	mu             sync.RWMutex
	matchingMode   config.CVEMatchingMode
	trustedVendors map[distro.Type]bool
	updating       bool
	updateChan     chan struct{}
	loadDB         loadDBFunc
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure
// DB loading is done via readiness probes
func NewGrypeAdapter(listingURL string, matchingMode config.CVEMatchingMode, trustedVendors []string) *GrypeAdapter {
	g := &GrypeAdapter{
		distCfg: distribution.Config{
			LatestURL: listingURL,
		},
		installCfg: installation.Config{
			DBRootDir: path.Join(xdg.CacheHome, "grype", "db"),
		},
		matchingMode:   matchingMode,
		trustedVendors: buildTrustedVendorSet(trustedVendors),
		loadDB:         defaultLoadDB,
	}
	return g
}

// buildTrustedVendorSet maps configured vendor slugs to Grype distro types.
func buildTrustedVendorSet(vendors []string) map[distro.Type]bool {
	set := make(map[distro.Type]bool, len(vendors))
	for _, v := range vendors {
		set[distro.Type(v)] = true
	}
	return set
}

func startGrypeOfflineDBContainer(ctx context.Context) (port string, terminate func(), err error) {
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/kubescape/grype-offline-db:v6-ci-only",
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP("/databases/v6/latest.json").WithPort("8080/tcp"),
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
	return NewGrypeAdapterFixedDBWithMatchers(config.CVEMatchingOn, nil)
}

// NewGrypeAdapterFixedDBWithMatchers is like NewGrypeAdapterFixedDB but lets
// callers exercise the same matcher mode as production (see NewGrypeAdapter).
func NewGrypeAdapterFixedDBWithMatchers(matchingMode config.CVEMatchingMode, trustedVendors []string) (*GrypeAdapter, func(), error) {
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
		matchingMode:   matchingMode,
		trustedVendors: buildTrustedVendorSet(trustedVendors),
		loadDB:         defaultLoadDB,
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

// Ready returns the status of the vulnerabilities DB, triggering non-blocking background updates as needed.
func (g *GrypeAdapter) Ready(ctx context.Context) bool {
	g.mu.RLock()
	hasValidDB := g.store != nil && g.dbStatus != nil && g.dbStatus.Error == nil
	needsUpdate := g.dbStatus == nil || time.Since(g.lastDbUpdate) > 24*time.Hour
	isUpdating := g.updating
	g.mu.RUnlock()

	if needsUpdate && !isUpdating {
		g.mu.Lock()
		if (g.dbStatus == nil || time.Since(g.lastDbUpdate) > 24*time.Hour) && !g.updating {
			g.updating = true
			g.updateChan = make(chan struct{})
			g.mu.Unlock()

			go g.updateDBBackground(ctx)
		} else {
			g.mu.Unlock()
		}
	}

	// On cold start (no DB loaded yet), wait for the initial background update to finish or context to cancel
	if !hasValidDB {
		g.mu.RLock()
		ch := g.updateChan
		g.mu.RUnlock()
		if ch != nil {
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.store != nil && g.dbStatus != nil && g.dbStatus.Error == nil
}

func (g *GrypeAdapter) updateDBBackground(ctx context.Context) {
	defer func() {
		g.mu.Lock()
		g.updating = false
		if g.updateChan != nil {
			close(g.updateChan)
			g.updateChan = nil
		}
		g.mu.Unlock()
	}()

	// Use context.WithoutCancel to prevent the update from being cancelled if the request context (e.g. readiness probe) is cancelled
	ctx, span := otel.Tracer("").Start(context.WithoutCancel(ctx), "GrypeAdapter.UpdateDB")
	defer span.End()
	logger.L().Info("updating grype DB",
		helpers.String("listingURL", g.distCfg.LatestURL))

	// Create a context with timeout to prevent stuck updates
	updateCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	g.mu.RLock()
	hasExistingDB := g.store != nil
	g.mu.RUnlock()

	type updateResult struct {
		store    vulnerability.Provider
		dbStatus *vulnerability.ProviderStatus
		err      error
	}
	resultCh := make(chan updateResult, 1)

	loadFn := g.loadDB
	if loadFn == nil {
		loadFn = defaultLoadDB
	}

	go func() {
		if logger.L().GetLevel() == "debug" {
			if distClient, err := distribution.NewClient(g.distCfg); err == nil {
				if archive, err := distClient.IsUpdateAvailable(nil); err == nil && archive != nil {
					if archiveURL, err := distClient.ResolveArchiveURL(*archive); err == nil {
						logger.L().Debug("downloading grype DB", helpers.String("archiveURL", archiveURL))
					}
				}
			}
		}
		if err := checkDBDirWritable(g.installCfg.DBRootDir); err != nil {
			logger.L().Ctx(ctx).Warning("grype DB root dir is not writable",
				helpers.Error(err),
				helpers.String("dbRootDir", g.installCfg.DBRootDir))
		}
		store, dbStatus, err := loadFn(g.distCfg, g.installCfg)
		resultCh <- updateResult{store: store, dbStatus: dbStatus, err: err}
	}()

	select {
	case result := <-resultCh:
		now := time.Now()
		if result.err != nil {
			logger.L().Ctx(ctx).Error("failed to update grype DB", helpers.Error(result.err))
			g.mu.Lock()
			if !hasExistingDB {
				err := tools.DeleteContents(g.installCfg.DBRootDir)
				logger.L().Debug("cleaned up cache", helpers.Error(err),
					helpers.String("DBRootDir", g.installCfg.DBRootDir))
			}
			// Schedule retry in 5 minutes on update failure
			g.lastDbUpdate = now.Add(-24*time.Hour + 5*time.Minute)
			g.mu.Unlock()
			return
		}
		g.mu.Lock()
		oldStore := g.store
		g.store = result.store
		g.dbStatus = result.dbStatus
		g.lastDbUpdate = now
		g.mu.Unlock()

		if oldStore != nil {
			if err := oldStore.Close(); err != nil {
				logger.L().Ctx(ctx).Warning("failed to close previous grype DB", helpers.Error(err))
			}
		}
		logger.L().Info("grype DB updated")
	case <-updateCtx.Done():
		// Drain resultCh asynchronously in case LoadVulnerabilityDB completes after timeout, preventing provider leak
		go func() {
			res := <-resultCh
			if res.store != nil {
				_ = res.store.Close()
			}
		}()

		now := time.Now()
		g.mu.Lock()
		if hasExistingDB {
			logger.L().Ctx(ctx).Warning("grype DB update timed out after 15 minutes, continuing with existing DB",
				helpers.String("existingDBVersion", g.dbVersionLocked()))
			// Delay retry for 1 hour on timeout
			g.lastDbUpdate = now.Add(-24*time.Hour + 1*time.Hour)
		} else {
			logger.L().Ctx(ctx).Error("grype DB initial download timed out after 15 minutes")
			err := tools.DeleteContents(g.installCfg.DBRootDir)
			logger.L().Debug("cleaned up cache after timeout", helpers.Error(err),
				helpers.String("DBRootDir", g.installCfg.DBRootDir))
			// Back-date to retry in 5 minutes
			g.lastDbUpdate = now.Add(-24*time.Hour + 5*time.Minute)
		}
		g.mu.Unlock()
	}
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
	useDefaultMatchers := g.resolveUseDefaultMatchers(dist)
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: g.store,
		Matchers:              getMatchers(useDefaultMatchers),
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

	// record the matching mode so backend/UI can explain count differences;
	// when adaptive mode actually downgraded this scan to a trusted vendor's
	// feed, flag the matched vendor distro as well.
	sbom.Annotations[CVEMatchingModeMetadataKey] = string(g.matchingMode)
	if g.matchingMode == config.CVEMatchingAdaptive && useDefaultMatchers && dist != nil {
		sbom.Annotations[VendorTrustedMatchMetadataKey] = dist.Type.String()
	}

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

// resolveUseDefaultMatchers decides, for a single scan, whether to use Grype's
// default (CPE-off) matcher configuration. In adaptive mode this is true only
// when the scanned image's distro is a trusted vendor, so CPE name-fuzzing is
// dropped in favour of the vendor's authoritative feed.
func (g *GrypeAdapter) resolveUseDefaultMatchers(dist *distro.Distro) bool {
	switch g.matchingMode {
	case config.CVEMatchingOff:
		return true
	case config.CVEMatchingOn:
		return false
	case config.CVEMatchingAdaptive:
		return dist != nil && g.trustedVendors[dist.Type]
	default:
		// LoadConfig rejects unknown modes, but NewGrypeAdapter is exported and
		// takes a raw mode; fall back to CPE-on (the safe, no-false-negative choice).
		return false
	}
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

// checkDBDirWritable probes write access by creating and immediately removing a temp file.
func checkDBDirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return err
	}
	f.Close()
	os.Remove(f.Name())
	return nil
}

// Version returns Grype's version which is used to tag CVE manifests
func (g *GrypeAdapter) Version() string {
	v := tools.PackageVersion("github.com/anchore/grype")
	v += "-matching-" + string(g.matchingMode)
	return v
}
