//go:build !nodockerfixture

// NewGrypeAdapterFixedDB and its helpers below spin up a real, pinned grype-DB container via
// testcontainers-go so grype_test.go and core/services/scan_test.go can exercise GrypeAdapter
// against a real vulnerability DB instead of the network. They exist only for tests -- no
// production code path calls them -- but living in an ordinary .go file meant
// testcontainers-go's own dependency tree (github.com/docker/docker and friends) was compiled
// into the production kubevuln binary regardless, carrying whatever CVEs that tree currently
// has for a binary that can never actually reach them (see #929; contrast with #854, which is
// a genuinely reachable one).
//
// The !nodockerfixture build tag keeps this file part of the default build -- go test ./...
// (as CI already runs it, unchanged) still compiles and runs these tests exactly as before --
// while make build and the Dockerfiles pass -tags nodockerfixture specifically for the
// binaries that ship, excluding this file (and therefore testcontainers-go) from them. See
// Makefile's build target and build/Dockerfile.
package v1

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/kubescape/kubevuln/config"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

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
			DBRootDir: filepath.Join(xdg.CacheHome, "grype-offline", "db"),
		},
		matchingMode:   matchingMode,
		trustedVendors: buildTrustedVendorSet(trustedVendors),
		loadDB:         defaultLoadDB,
	}
	return g, terminate, nil
}
