package v1

import (
	"context"
	"errors"
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
	// nextUpdateAttempt is when Ready may next launch a background update. It is set on
	// every terminal outcome of updateDBBackground (success -> +24h, failure -> +5m) and
	// gates retries independently of dbStatus, so a cold start that keeps failing (and
	// therefore never sets dbStatus) still backs off between attempts instead of firing
	// once per readiness probe.
	nextUpdateAttempt time.Time
	dbStatus          *vulnerability.ProviderStatus
	store             vulnerability.Provider
	distCfg           distribution.Config
	installCfg        installation.Config
	mu                sync.RWMutex
	matchingMode      config.CVEMatchingMode
	trustedVendors    map[distro.Type]bool
	updating          bool
	updateChan        chan struct{}
	loadDB            loadDBFunc
}

var _ ports.CVEScanner = (*GrypeAdapter)(nil)

// NewGrypeAdapter initializes the GrypeAdapter structure
// DB loading is done via readiness probes
func NewGrypeAdapter(listingURL string, matchingMode config.CVEMatchingMode, trustedVendors []string) *GrypeAdapter {
	distCfg := distribution.DefaultConfig()
	distCfg.LatestURL = listingURL
	g := &GrypeAdapter{
		distCfg: distCfg,
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
//
// Grype's distro types are lowercase slugs that it compares verbatim, so a configured slug
// is normalised rather than taken as written: "Wolfi", or one with the whitespace a JSON
// list easily carries, would otherwise sit in the set as a key no distro ever matches, and
// the vendor would stay untrusted with nothing to say so. A slug that is not one of Grype's
// types cannot match either, so it is called out for the same reason: adaptive mode is meant
// to turn CPE matching off for these vendors, and a typo silently leaves it on.
func buildTrustedVendorSet(vendors []string) map[distro.Type]bool {
	known := make(map[distro.Type]bool, len(distro.All))
	for _, t := range distro.All {
		known[t] = true
	}

	set := make(map[distro.Type]bool, len(vendors))
	for _, v := range vendors {
		slug := distro.Type(strings.ToLower(strings.TrimSpace(v)))
		if slug == "" {
			continue
		}
		if !known[slug] {
			// Kept in the set regardless: it can never match, and dropping it would be a
			// second silent behaviour rather than a reported one.
			logger.L().Warning("trusted vendor is not a distro Grype recognizes, it will never match",
				helpers.String("vendor", v))
		}
		set[slug] = true
	}
	return set
}

// ErrDockerUnavailable is returned (wrapped) when no usable container runtime
// could be reached. Callers that only want to skip on environment unavailability
// -- as opposed to failing on genuine container setup errors (bad image, registry,
// port mapping, ...) -- should check for it with errors.Is.
var ErrDockerUnavailable = errors.New("container runtime unavailable")

// probeDockerAvailable checks whether a usable container runtime is reachable
// before attempting to start a testcontainers-go container. testcontainers-go's
// docker host detection can panic (instead of returning an error) in some
// misconfigured environments (e.g. rootless Docker it fails to detect), so a
// recover is also in place as a defense in depth. Every error returned here
// wraps ErrDockerUnavailable.
func probeDockerAvailable(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("docker runtime probe panicked: %v: %w", r, ErrDockerUnavailable)
		}
	}()

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return fmt.Errorf("docker provider unavailable: %w: %w", err, ErrDockerUnavailable)
	}
	defer provider.Close()

	if err := provider.Health(ctx); err != nil {
		return fmt.Errorf("docker daemon not healthy: %w: %w", err, ErrDockerUnavailable)
	}
	return nil
}

func startGrypeOfflineDBContainer(ctx context.Context) (port string, terminate func(), err error) {
	terminate = func() {}

	if probeErr := probeDockerAvailable(ctx); probeErr != nil {
		return "", terminate, fmt.Errorf("container runtime not available: %w", probeErr)
	}

	// Panics past this point happen while actually starting the container (bad
	// image, registry, port mapping, ...) rather than because the runtime itself
	// is unavailable -- the availability probe above already ruled that out.
	// Recover so callers get a normal error instead of an unrecovered panic
	// crashing the whole test binary, but deliberately do NOT wrap
	// ErrDockerUnavailable here so callers still fail on these instead of skipping.
	// Note: if the panic happens after the container started, that container is
	// leaked since we have no reference to it here to terminate.
	defer func() {
		if r := recover(); r != nil {
			port = ""
			err = fmt.Errorf("starting grype offline db container panicked: %v", r)
		}
	}()

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
		return "", terminate, err
	}

	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		return "", terminate, err
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
		return nil, terminate, err
	}
	distCfg := distribution.DefaultConfig()
	distCfg.LatestURL = fmt.Sprintf("http://localhost:%s/databases", port)
	g := &GrypeAdapter{
		distCfg: distCfg,
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
	needsUpdate := time.Now().After(g.nextUpdateAttempt)
	isUpdating := g.updating
	g.mu.RUnlock()

	if needsUpdate && !isUpdating {
		g.mu.Lock()
		if time.Now().After(g.nextUpdateAttempt) && !g.updating {
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

// updateDBBackground launches the actual DB load in its own goroutine and waits up to 15
// minutes for it, purely so a slow/stuck download doesn't hold up this goroutine forever.
// grype.LoadVulnerabilityDB takes no context and cannot be cancelled, so giving up on the
// wait does NOT stop the load - it keeps writing to installCfg.DBRootDir in the background.
// Consequently every mutation of shared state (installing a successful result, scheduling
// the next attempt, releasing the single-flight guard, and cleaning up DBRootDir on failure)
// happens exactly once, in finishUpdate, invoked by the goroutine that actually ran the load
// - never here. That is what keeps a slow load from racing a second one started by the next
// readiness probe, and keeps DBRootDir from being wiped out from under a download still
// writing to it.
func (g *GrypeAdapter) updateDBBackground(ctx context.Context) {
	// Use context.WithoutCancel to prevent the update from being cancelled if the request context (e.g. readiness probe) is cancelled
	ctx, span := otel.Tracer("").Start(context.WithoutCancel(ctx), "GrypeAdapter.UpdateDB")
	defer span.End()
	logger.L().Info("updating grype DB",
		helpers.String("listingURL", g.distCfg.LatestURL))

	g.mu.RLock()
	hasExistingDB := g.store != nil
	g.mu.RUnlock()

	// loadDB is set once at construction and never reassigned afterwards, so reading it
	// here without g.mu is safe even though every other field on GrypeAdapter is guarded.
	loadFn := g.loadDB
	if loadFn == nil {
		loadFn = defaultLoadDB
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

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
		g.finishUpdate(ctx, hasExistingDB, store, dbStatus, err)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Minute):
		// grype.LoadVulnerabilityDB takes no context and cannot be cancelled, and the
		// pinned grype's HTTP client bounds only dial/TLS handshake, not response-body
		// reads (its withUserAgent post-processor replaces the *http.Client wholesale,
		// silently dropping any Timeout we set on distCfg). A connection that stalls
		// mid-download therefore hangs the load goroutine forever, so finishUpdate would
		// never run: updating would stay true and DBRootDir would never be retried.
		//
		// On a cold start there is nothing to lose, so restart - the one case where this
		// loses non-blocking behaviour is a download that is genuinely stuck, not merely
		// slow, which is the same condition that used to trigger os.Exit(0) unconditionally
		// before this PR. With an existing DB, though, the pod is healthy and serving: keep
		// it that way instead of dropping in-flight scans, and let finishUpdate install the
		// stuck load whenever (if ever) it returns.
		if !hasExistingDB {
			logger.L().Ctx(ctx).Error("grype DB initial download stuck past 15 minutes with an uncancellable load in flight, restarting to recover")
			os.Exit(0)
		}
		g.mu.RLock()
		existingVersion := g.dbVersionLocked()
		g.mu.RUnlock()
		logger.L().Ctx(ctx).Error("grype DB update stuck past 15 minutes with an uncancellable load in flight, continuing with existing DB",
			helpers.String("existingDBVersion", existingVersion))
	}
}

// finishUpdate is invoked exactly once per updateDBBackground call, by the goroutine that
// actually ran loadFn, regardless of whether updateDBBackground's own 15-minute wait already
// gave up on it. It owns every mutation of shared state for this update - installing a
// successful result, scheduling the next attempt, and releasing the single-flight guard -
// so nothing else can delete DBRootDir or start a second update while this one is still
// writing to it. Installing the new state happens under g.mu, but the actual I/O (closing
// providers, deleting DBRootDir) happens after unlocking, so scans only block for the pointer
// swap. The single-flight guard is released only after that I/O completes: Ready() unblocks
// cold-start callers as soon as updateChan closes, so closing it any earlier would let a
// caller observe g.store before an unusable one has actually been Close()'d.
func (g *GrypeAdapter) finishUpdate(ctx context.Context, hasExistingDB bool, store vulnerability.Provider, dbStatus *vulnerability.ProviderStatus, err error) {
	now := time.Now()

	// Released last via defer, after any I/O below, no matter which branch runs or how it
	// returns: a leaked updating=true would permanently wedge future updates, since nothing
	// else ever clears it, so this must not depend on every branch remembering to call it.
	defer func() {
		g.mu.Lock()
		g.updating = false
		if g.updateChan != nil {
			close(g.updateChan)
			g.updateChan = nil
		}
		g.mu.Unlock()
	}()

	// A successful load whose reported status still carries an error is not usable: treat
	// it the same as a load failure so Ready() keeps reporting not-ready and a retry gets
	// scheduled, instead of wedging the pod NotReady for 24h with nothing to recover it.
	if err == nil && dbStatus != nil && dbStatus.Error != nil {
		err = dbStatus.Error
	}

	if err != nil {
		g.mu.Lock()
		// Schedule retry in 5 minutes on update failure
		g.nextUpdateAttempt = now.Add(5 * time.Minute)
		g.mu.Unlock()

		logger.L().Ctx(ctx).Error("failed to update grype DB", helpers.Error(err))
		if store != nil {
			if closeErr := store.Close(); closeErr != nil {
				logger.L().Ctx(ctx).Warning("failed to close grype DB opened despite reported status error", helpers.Error(closeErr))
			}
		}
		if !hasExistingDB {
			if delErr := tools.DeleteContents(g.installCfg.DBRootDir); delErr != nil {
				logger.L().Ctx(ctx).Warning("failed to clean up grype DB cache", helpers.Error(delErr),
					helpers.String("DBRootDir", g.installCfg.DBRootDir))
			}
		}
		return
	}

	g.mu.Lock()
	oldStore := g.store
	g.store = store
	g.dbStatus = dbStatus
	// Schedule the next routine refresh in 24 hours
	g.nextUpdateAttempt = now.Add(24 * time.Hour)
	g.mu.Unlock()

	if oldStore != nil && oldStore != store {
		if closeErr := oldStore.Close(); closeErr != nil {
			logger.L().Ctx(ctx).Warning("failed to close previous grype DB", helpers.Error(closeErr))
		}
	}
	logger.L().Info("grype DB updated")
}

const dummyLayer = "generatedlayer"

// ScanSBOM generates a CVE manifest by scanning an SBOM
func (g *GrypeAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	ctx, span := otel.Tracer("").Start(ctx, "GrypeAdapter.ScanSBOM")
	defer span.End()

	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.store == nil || g.dbStatus == nil || g.dbStatus.Error != nil {
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
