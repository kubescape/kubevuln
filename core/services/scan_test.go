package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/scanfailure"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/docker/docker/api/types/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestScanService_GenerateSBOM(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		sbom            domain.SBOM
		storage         bool
		getError        bool
		storeError      bool
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantErr         bool
		// wantReason, when non-empty, asserts the error GenerateSBOM returns is a
		// *domain.ScanError carrying this scanfailure.Reason* value (see #540).
		wantReason string
	}{
		{
			name:     "phase 1, no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "phase 1",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "phase 1, createSBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:       "phase 1, timeout",
			timeout:    true,
			workload:   true,
			wantErr:    true,
			wantReason: scanfailure.ReasonSBOMIncomplete,
		},
		{
			name:            "phase 1, too many requests",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:     "phase 2, get SBOM failed",
			storage:  true,
			getError: true,
			workload: true,
			wantErr:  false,
		},
		{
			name:       "phase 2, store SBOM failed",
			storage:    true,
			storeError: true,
			workload:   true,
			wantErr:    true,
			wantReason: scanfailure.ReasonSBOMStorageFailed,
		},
		{
			name:     "phase 2, create and store SBOM",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			storage := repositories.NewMemoryStorage(tt.getError, tt.storeError)
			s := NewScanService(sbomAdapter, storage, adapters.NewMockCVEAdapter(), storage, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), tt.storage, false, true, false, false)
			ctx := context.TODO()

			workload := domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			}
			workload.CredentialsList = []registry.AuthConfig{
				{
					Username: "test",
					Password: "test",
				},
				{
					RegistryToken: "test",
				},
				{
					Auth: "test",
				},
			}
			workload.Args = map[string]interface{}{
				domain.AttributeUseHTTP:       false,
				domain.AttributeSkipTLSVerify: false,
			}
			if tt.workload {
				ctx, _ = s.ValidateGenerateSBOM(ctx, workload)
			}
			err := s.GenerateSBOM(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, err := s.ValidateGenerateSBOM(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, err)
			}
			if tt.wantReason != "" {
				var scanErr *domain.ScanError
				require.ErrorAsf(t, err, &scanErr, "expected a *domain.ScanError, got %T: %v", err, err)
				assert.Equal(t, tt.wantReason, scanErr.Reason)
			}
			if tt.timeout {
				// a timed-out/too-large SBOM must be surfaced as a failure (see #540), not
				// silently stored and reported as success like every other scan flow already does
				assert.ErrorIs(t, err, domain.ErrIncompleteSBOM)
			}
		})
	}
}

// perImageSBOMCreator names each SBOM after the slug it was asked for, and holds every
// caller inside CreateSBOM until all of them have arrived, so the callers provably contend
// rather than finishing one after another.
type perImageSBOMCreator struct {
	calls   int32
	arrived int32
	total   int32
	all     chan struct{}
}

func (c *perImageSBOMCreator) CreateSBOM(_ context.Context, name, _, _ string, _ domain.RegistryOptions) (domain.SBOM, error) {
	atomic.AddInt32(&c.calls, 1)
	if atomic.AddInt32(&c.arrived, 1) == c.total {
		close(c.all)
	}
	// Bounded, because the point of the test is that both callers get here. If they are
	// merged onto one key only one ever does, and an unbounded wait would hang instead of
	// failing on the assertion below.
	select {
	case <-c.all:
	case <-time.After(2 * time.Second):
	}
	return domain.SBOM{Name: name, SBOMCreatorVersion: c.Version(), Content: &v1beta1.SyftDocument{}}, nil
}

func (c *perImageSBOMCreator) Version() string        { return "Mock SBOM 1.0" }
func (c *perImageSBOMCreator) GetMaxImageSize() int64 { return 0 }
func (c *perImageSBOMCreator) GetMaxSBOMSize() int    { return 0 }
func (c *perImageSBOMCreator) GetMemoryLimit() string { return "" }

// A mutable tag can point at two digests at once, mid-rollout or after a repush. Those are
// different images, stored under different slugs, so they must not be deduplicated into one
// another: the loser would be handed an SBOM for an image it is not scanning, and since the
// CVE manifest takes its name from the SBOM, its findings would be filed under the other
// image's slug.
func TestScanService_getOrCreateSBOM_SameTagDifferentDigestsAreNotShared(t *testing.T) {
	creator := &perImageSBOMCreator{total: 2, all: make(chan struct{})}
	store := repositories.NewMemoryStorage(false, false)
	// storage off: this is about which callers share a key, and MemoryStore's maps are
	// unguarded, so two workers storing at once race the double rather than the code.
	s := NewScanService(creator, store, adapters.NewMockCVEAdapter(), store, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)

	workloads := []domain.ScanCommand{
		{ImageTagNormalized: "repo/app:latest", ImageHash: "sha256:aaaaaaaaaaaa", ImageSlug: "repo-app-latest-aaaaaaaaaaaa"},
		{ImageTagNormalized: "repo/app:latest", ImageHash: "sha256:bbbbbbbbbbbb", ImageSlug: "repo-app-latest-bbbbbbbbbbbb"},
	}

	names := make([]string, len(workloads))
	var wg sync.WaitGroup
	for i := range workloads {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sbom, _, err := s.getOrCreateSBOM(context.TODO(), workloads[i])
			assert.NoError(t, err)
			names[i] = sbom.Name
		}(i)
	}
	wg.Wait()

	for i, w := range workloads {
		assert.Equal(t, w.ImageSlug, names[i], "each workload must get the SBOM for its own image")
	}
	assert.Equal(t, int32(2), atomic.LoadInt32(&creator.calls), "two digests are two images, not one")
}

// sizeCappedSBOMCreator mirrors the TooLarge path in adapters/v1/syft.go, which returns
// before Content is ever assigned: the SBOM carries a status and the annotations getSBOM
// re-checks against the current limits, but no document. NewMockSBOMAdapter cannot stand in
// here, as it always fills Content.
type sizeCappedSBOMCreator struct {
	calls int
	// status is what the adapter settled on, TooLarge or Incomplete. Both come back with no
	// document; only TooLarge carries the limit annotations getSBOM re-checks.
	status string
}

func (c *sizeCappedSBOMCreator) CreateSBOM(_ context.Context, name, _, _ string, _ domain.RegistryOptions) (domain.SBOM, error) {
	c.calls++
	sbom := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: c.Version(),
		Status:             c.status,
	}
	if c.status == helpersv1.TooLarge {
		sbom.Annotations = map[string]string{
			domain.StatusReasonAnnotationKey: domain.ReasonImageTooLarge,
			domain.MaxImageSizeAnnotationKey: "512",
		}
	}
	return sbom, nil
}

func (c *sizeCappedSBOMCreator) Version() string        { return "Mock SBOM 1.0" }
func (c *sizeCappedSBOMCreator) GetMaxImageSize() int64 { return 512 }
func (c *sizeCappedSBOMCreator) GetMaxSBOMSize() int    { return 0 }
func (c *sizeCappedSBOMCreator) GetMemoryLimit() string { return "" }

func generateSBOMContext(t *testing.T, s *ScanService) context.Context {
	t.Helper()
	ctx, err := s.ValidateGenerateSBOM(context.TODO(), domain.ScanCommand{
		ImageSlug: "imageSlug",
		ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
	})
	require.NoError(t, err)
	return ctx
}

// A TooLarge or Incomplete SBOM has no Content, so gating the store on Content meant the
// verdict was never written and every later scan of that image pulled it again to reach the
// same answer. StoreSBOM persists it as a status-only marker precisely so it can be reused.
func TestScanService_GenerateSBOM_RemembersTooLargeVerdict(t *testing.T) {
	creator := &sizeCappedSBOMCreator{status: helpersv1.TooLarge}
	storage := repositories.NewMemoryStorage(false, false)
	s := NewScanService(creator, storage, adapters.NewMockCVEAdapter(), storage, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), true, false, true, false, false)
	ctx := generateSBOMContext(t, s)

	assert.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM)
	require.Equal(t, 1, storage.SBOMStores(), "the verdict must be persisted")
	require.Equal(t, 1, creator.calls)

	assert.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM, "still a failure")
	assert.Equal(t, 1, creator.calls, "the stored verdict must be reused, not recomputed")
	assert.Equal(t, 1, storage.SBOMStores(), "and not written again on the way through")
}

// Incomplete is the other status that comes back without a document, but it means the scan
// timed out, and getSBOM has no staleness rule for it. Stored, it would read back as a
// cache hit at the same scanner version forever and no retry would ever happen.
func TestScanService_GenerateSBOM_DoesNotPersistIncompleteVerdict(t *testing.T) {
	creator := &sizeCappedSBOMCreator{status: helpersv1.Incomplete}
	storage := repositories.NewMemoryStorage(false, false)
	s := NewScanService(creator, storage, adapters.NewMockCVEAdapter(), storage, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), true, false, true, false, false)
	ctx := generateSBOMContext(t, s)

	assert.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM)
	assert.Equal(t, 0, storage.SBOMStores(), "a timeout must not be persisted")

	assert.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM)
	assert.Equal(t, 2, creator.calls, "and must be retried on the next scan")
}

// getOrCreateSBOM stores what it creates, so storing again in the flow wrote the same
// document to the apiserver twice.
func TestScanService_GenerateSBOM_StoresCreatedSBOMOnce(t *testing.T) {
	storage := repositories.NewMemoryStorage(false, false)
	s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false), storage, adapters.NewMockCVEAdapter(), storage, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), true, false, true, false, false)
	ctx := generateSBOMContext(t, s)

	require.NoError(t, s.GenerateSBOM(ctx))
	assert.Equal(t, 1, storage.SBOMStores(), "a newly created SBOM must be stored once")

	// the second call is served from storage, and StoreSBOM is a Create that falls back to
	// Get plus a full Update of the spec, so writing it back is not free
	require.NoError(t, s.GenerateSBOM(ctx))
	assert.Equal(t, 1, storage.SBOMStores(), "an SBOM read back from storage must not be stored again")
}

func TestScanService_ScanCP(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		slug            string
		emptyWlid       bool
		cveManifest     bool
		sbom            bool
		storage         bool
		getErrorCVE     bool
		getErrorSBOM    bool
		storeErrorCVE   bool
		storeErrorSBOM  bool
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantCvep        bool
		wantEmptyReport bool
		wantErr         bool
	}{
		{
			name:    "no workload",
			wantErr: true,
		},
		{
			name:     "no storage",
			workload: true,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
		},
		{
			name:            "create SBOM too many requests",
			toomanyrequests: true,
			workload:        true,
		},
		{
			name:      "empty wlid",
			emptyWlid: true,
			storage:   true,
			workload:  true,
		},
		{
			name:     "first scan",
			storage:  true,
			workload: true,
		},
		{
			name:        "second scan",
			storage:     true,
			cveManifest: true,
			sbom:        true,
			workload:    true,
		},
		{
			name:         "get SBOM failed",
			getErrorSBOM: true,
			storage:      true,
			workload:     true,
		},
		{
			name:           "store SBOM failed",
			storeErrorSBOM: true,
			storage:        true,
			workload:       true,
		},
		{
			name:        "get CVE failed",
			getErrorCVE: true,
			storage:     true,
			workload:    true,
		},
		{
			name:          "store CVE failed",
			storeErrorCVE: true,
			storage:       true,
			workload:      true,
		},
		{
			name:     "timeout SBOM",
			sbom:     true,
			storage:  true,
			timeout:  true,
			workload: true,
		},
		{
			name:     "with SBOMp",
			sbom:     true,
			slug:     "daemonset-kube-proxy-kube-proxy-4e8b-ad45",
			storage:  true,
			workload: true,
			wantCvep: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
			if tt.emptyWlid {
				wlid = ""
			}
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			cveAdapter := adapters.NewMockCVEAdapter()
			storageCP := repositories.NewMemoryStorage(false, false)
			storageSBOM := repositories.NewMemoryStorage(tt.getErrorSBOM, tt.storeErrorSBOM)
			storageCVE := repositories.NewMemoryStorage(tt.getErrorCVE, tt.storeErrorCVE)
			s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, adapters.NewMockPlatform(tt.wantEmptyReport, nil), v1.NewContainerProfileAdapter(storageCP), tt.storage, false, true, false, false)
			ctx := context.TODO()
			s.Ready(ctx)

			workload := domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName:      "daemonset-kube-proxy",
					domain.ArgsNamespace: "kube-system",
				},
				Wlid: wlid,
			}
			imageID := "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			imageTag := "k8s.gcr.io/kube-proxy:v1.24.3"
			if tt.workload {
				var err error
				ctx, err = s.ValidateScanCP(ctx, workload)
				require.NoError(t, err)
			}
			if tt.sbom {
				sbom, err := sbomAdapter.CreateSBOM(ctx, "imageSlug", imageHash, "", domain.RegistryOptions{})
				require.NoError(t, err)
				_ = storageSBOM.StoreSBOM(ctx, sbom, false)
				if tt.cveManifest {
					cve, err := cveAdapter.ScanSBOM(ctx, sbom)
					require.NoError(t, err)
					_ = storageCVE.StoreCVE(ctx, cve, false)
				}
			}
			ap := v1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "daemonset-kube-proxy",
					Namespace: "kube-system",
					Annotations: map[string]string{
						helpersv1.CompletionMetadataKey: helpersv1.Full,
						helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-kube-system/kind-DaemonSet/name-kube-proxy/containerName-kube-proxy",
						helpersv1.StatusMetadataKey:     helpersv1.Learning,
						helpersv1.WlidMetadataKey:       wlid,
					},
					Labels: map[string]string{"foo": "bar"},
				},
				Spec: v1beta1.ContainerProfileSpec{
					Execs: []v1beta1.ExecCalls{
						{Path: "/usr/local/bin/kube-proxy"},
					},
					Opens: []v1beta1.OpenCalls{
						{Path: "/etc/kubernetes/kube-proxy.conf"},
					},
					ImageID:  imageID,
					ImageTag: imageTag,
				},
			}
			err := storageCP.StoreContainerProfile(ctx, ap)
			require.NoError(t, err)

			if err := s.ScanCP(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanCP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				// the 429 marker must be recorded under the same canonical key every
				// other flow uses (ImageTagNormalized, see rateLimitCacheKey), not the raw
				// container-profile ImageID, otherwise nothing will ever read it back
				_, ok := s.tooManyRequests.Get(tools.NormalizeReference(imageTag))
				assert.True(t, ok, "expected image to be recorded as rate limited under its normalized image reference")
			}
			if tt.wantCvep {
				cvep, err := storageCVE.GetCVE(ctx, tt.slug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx))
				require.NoError(t, err)
				assert.NotNil(t, cvep.Labels)
			}
		})
	}
}

// countingSBOMCreator wraps a ports.SBOMCreator and counts CreateSBOM invocations, so tests can
// assert a pull was (or wasn't) attempted without depending on ScanCP's returned error.
type countingSBOMCreator struct {
	ports.SBOMCreator
	calls int
}

func (c *countingSBOMCreator) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	c.calls++
	return c.SBOMCreator.CreateSBOM(ctx, name, imageID, imageTag, options)
}

// TestScanService_ScanCP_SkipsPullForAlreadyRateLimitedImage verifies that once an image has been
// recorded as rate limited (matching the key ScanCP itself writes under, see the
// "create SBOM too many requests" case above), a later ScanCP call for that same image does not
// attempt another pull. This is the read side of the bug: ValidateScanCP has no image identity to
// check ahead of time, so the gate has to live at the point ScanCP actually knows which image it's
// about to pull.
func TestScanService_ScanCP_SkipsPullForAlreadyRateLimitedImage(t *testing.T) {
	imageID := "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	imageTag := "k8s.gcr.io/kube-proxy:v1.24.3"
	wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"

	sbomAdapter := &countingSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)}
	cveAdapter := adapters.NewMockCVEAdapter()
	storageCP := repositories.NewMemoryStorage(false, false)
	storageSBOM := repositories.NewMemoryStorage(false, false)
	storageCVE := repositories.NewMemoryStorage(false, false)
	s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, adapters.NewMockPlatform(false, nil), v1.NewContainerProfileAdapter(storageCP), true, false, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)

	workload := domain.ScanCommand{
		Args: map[string]interface{}{
			domain.ArgsName:      "daemonset-kube-proxy",
			domain.ArgsNamespace: "kube-system",
		},
		Wlid: wlid,
	}
	ctx, err := s.ValidateScanCP(ctx, workload)
	require.NoError(t, err)

	ap := v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "daemonset-kube-proxy",
			Namespace: "kube-system",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-kube-system/kind-DaemonSet/name-kube-proxy/containerName-kube-proxy",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       wlid,
			},
			Labels: map[string]string{"foo": "bar"},
		},
		Spec: v1beta1.ContainerProfileSpec{
			ImageID:  imageID,
			ImageTag: imageTag,
		},
	}
	require.NoError(t, storageCP.StoreContainerProfile(ctx, ap))

	// simulate a prior pull of this exact image having already come back 429, recorded under
	// the canonical key ScanCP writes to (ImageTagNormalized, see rateLimitCacheKey)
	s.tooManyRequests.Set(tools.NormalizeReference(imageTag), true, ttl)

	require.NoError(t, s.ScanCP(ctx))
	assert.Equal(t, 0, sbomAdapter.calls, "ScanCP should not attempt to pull an image already known to be rate limited")
}

// TestIsRegistryRateLimitedErr is a regression test: checkCreateSBOM's rate-limit detection
// must not rely on errors.As(err, &transport.Error{}) alone, since a real pull error never
// reaches it in that shape. stereoscope's registry provider formats the go-containerregistry
// pull error with %+v, not %w, which severs the errors.As chain before CreateSBOM's error
// ever gets here — so a text fallback is required (mirrors
// pkg/sbomscanner/v1.isRegistryRateLimited, which has the identical problem on the sidecar
// side of the same pull path). This also covers the sidecar adapter's own signal:
// domain.ErrTooManyRequests, which adapters/v1 SidecarSBOMAdapter.CreateSBOM wraps instead of
// trying to reconstruct a *transport.Error across the gRPC boundary.
func TestIsRegistryRateLimitedErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "429 transport error",
			err:  &transport.Error{StatusCode: http.StatusTooManyRequests},
			want: true,
		},
		{
			name: "401 transport error is not rate limiting",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized},
			want: false,
		},
		{
			name: "domain.ErrTooManyRequests sentinel wrapped (sidecar path)",
			err:  fmt.Errorf("sidecar reported 429: %w", domain.ErrTooManyRequests),
			want: true,
		},
		{
			name: "wrapped via stereoscope's real %+v formatting (in-process syft path)",
			err:  fmt.Errorf("failed to get image descriptor from registry: %+v", &transport.Error{StatusCode: http.StatusTooManyRequests}),
			want: true,
		},
		{
			name: "generic message mentioning 429 alone is not enough",
			err:  errors.New("received status code: 429"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRegistryRateLimitedErr(tt.err))
		})
	}
}

func TestScanService_ScanCVE(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		slug            string
		emptyWlid       bool
		cveManifest     bool
		sbom            bool
		storage         bool
		getErrorCVE     bool
		getErrorSBOM    bool
		storeErrorCVE   bool
		storeErrorSBOM  bool
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantEmptyReport bool
		wantErr         bool
		// wantReason, when non-empty, asserts the error ScanCVE returns is a
		// *domain.ScanError carrying this scanfailure.Reason* value (see #540).
		wantReason string
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "no storage",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:            "create SBOM too many requests",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:      "empty wlid",
			emptyWlid: true,
			storage:   true,
			workload:  true,
			wantErr:   false,
		},
		{
			name:     "first scan",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
		{
			name:            "second scan",
			storage:         true,
			cveManifest:     true,
			sbom:            true,
			workload:        true,
			wantEmptyReport: false,
			wantErr:         false,
		},
		{
			name:         "get SBOM failed",
			getErrorSBOM: true,
			storage:      true,
			workload:     true,
			wantErr:      false,
		},
		{
			name:           "store SBOM failed",
			storeErrorSBOM: true,
			storage:        true,
			workload:       true,
			wantErr:        false,
		},
		{
			name:        "get CVE failed",
			getErrorCVE: true,
			storage:     true,
			workload:    true,
			wantErr:     false,
		},
		{
			name:          "store CVE failed",
			storeErrorCVE: true,
			storage:       true,
			workload:      true,
			wantErr:       false,
		},
		{
			name:       "timeout SBOM",
			sbom:       true,
			storage:    true,
			timeout:    true,
			workload:   true,
			wantErr:    true,
			wantReason: scanfailure.ReasonSBOMIncomplete,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
			if tt.emptyWlid {
				wlid = ""
			}
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			cveAdapter := adapters.NewMockCVEAdapter()
			storageCP := repositories.NewMemoryStorage(false, false)
			storageSBOM := repositories.NewMemoryStorage(tt.getErrorSBOM, tt.storeErrorSBOM)
			storageCVE := repositories.NewMemoryStorage(tt.getErrorCVE, tt.storeErrorCVE)
			s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, adapters.NewMockPlatform(tt.wantEmptyReport, nil), v1.NewContainerProfileAdapter(storageCP), tt.storage, false, true, false, false)
			ctx := context.TODO()
			s.Ready(ctx)

			workload := domain.ScanCommand{
				ImageSlug:     "imageSlug",
				ContainerName: "kube-proxy",
				ImageHash:     imageHash,
				Wlid:          wlid,
			}
			if tt.workload {
				var err error
				ctx, err = s.ValidateScanCVE(ctx, workload)
				require.NoError(t, err)
			}
			if tt.sbom {
				sbom, err := sbomAdapter.CreateSBOM(ctx, "imageSlug", imageHash, "", domain.RegistryOptions{})
				require.NoError(t, err)
				_ = storageSBOM.StoreSBOM(ctx, sbom, false)
				if tt.cveManifest {
					cve, err := cveAdapter.ScanSBOM(ctx, sbom)
					require.NoError(t, err)
					_ = storageCVE.StoreCVE(ctx, cve, false)
				}
			}
			err := s.ScanCVE(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, verr := s.ValidateScanCVE(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, verr)
			}
			if tt.wantReason != "" {
				var scanErr *domain.ScanError
				require.ErrorAsf(t, err, &scanErr, "expected a *domain.ScanError, got %T: %v", err, err)
				assert.Equal(t, tt.wantReason, scanErr.Reason)
			}
			if tt.timeout {
				assert.ErrorIs(t, err, domain.ErrIncompleteSBOM)
			}
		})
	}
}

// schemaUnsupportedSBOMAdapter is a mock SBOMCreator that always fails with a
// registry schema-unsupported error, used to exercise the per-workload stub summary path.
type schemaUnsupportedSBOMAdapter struct{}

func (schemaUnsupportedSBOMAdapter) CreateSBOM(_ context.Context, _, _, _ string, _ domain.RegistryOptions) (domain.SBOM, error) {
	return domain.SBOM{}, fmt.Errorf("creating SBOM: oci-registry: failed to get image descriptor from registry: MANIFEST_SCHEMA_UNSUPPORTED: manifest schema unsupported")
}

func (schemaUnsupportedSBOMAdapter) Version() string { return "schema-unsupported-mock" }

func (schemaUnsupportedSBOMAdapter) GetMaxImageSize() int64 { return 0 }
func (schemaUnsupportedSBOMAdapter) GetMaxSBOMSize() int    { return 0 }
func (schemaUnsupportedSBOMAdapter) GetMemoryLimit() string { return "" }

func TestScanService_ScanCVE_SchemaUnsupportedStub(t *testing.T) {
	imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
	workload := domain.ScanCommand{
		ImageSlug:     "imageSlug",
		ContainerName: "kube-proxy",
		ImageHash:     imageHash,
		Wlid:          wlid,
	}

	t.Run("schema-unsupported error writes a stub summary", func(t *testing.T) {
		storageCVE := repositories.NewMemoryStorage(false, false)
		s := NewScanService(schemaUnsupportedSBOMAdapter{}, repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), storageCVE, adapters.NewMockPlatform(false, nil), v1.NewContainerProfileAdapter(repositories.NewMemoryStorage(false, false)), true, false, true, false, false)
		ctx := context.TODO()
		s.Ready(ctx)
		ctx, err := s.ValidateScanCVE(ctx, workload)
		require.NoError(t, err)
		require.Error(t, s.ScanCVE(ctx))
		assert.Equal(t, []string{helpersv1.UnsupportedSchema}, storageCVE.CVESummaryStubs())
	})

	t.Run("generic SBOM error does not write a stub summary", func(t *testing.T) {
		storageCVE := repositories.NewMemoryStorage(false, false)
		s := NewScanService(adapters.NewMockSBOMAdapter(true, false, false), repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), storageCVE, adapters.NewMockPlatform(false, nil), v1.NewContainerProfileAdapter(repositories.NewMemoryStorage(false, false)), true, false, true, false, false)
		ctx := context.TODO()
		s.Ready(ctx)
		ctx, err := s.ValidateScanCVE(ctx, workload)
		require.NoError(t, err)
		require.Error(t, s.ScanCVE(ctx))
		assert.Empty(t, storageCVE.CVESummaryStubs())
	})

	t.Run("image-only scan (empty wlid) does not write a stub summary", func(t *testing.T) {
		storageCVE := repositories.NewMemoryStorage(false, false)
		s := NewScanService(schemaUnsupportedSBOMAdapter{}, repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), storageCVE, adapters.NewMockPlatform(false, nil), v1.NewContainerProfileAdapter(repositories.NewMemoryStorage(false, false)), true, false, true, false, false)
		ctx := context.TODO()
		s.Ready(ctx)
		imageOnly := domain.ScanCommand{
			ImageSlug: "imageSlug",
			ImageHash: imageHash,
		}
		ctx, err := s.ValidateScanCVE(ctx, imageOnly)
		require.NoError(t, err)
		require.Error(t, s.ScanCVE(ctx))
		assert.Empty(t, storageCVE.CVESummaryStubs(), "image-only scan must not attempt a per-workload stub")
	})
}

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func fileToSyftDocument(path string) *v1beta1.SyftDocument {
	sbom := v1beta1.SyftDocument{}
	_ = json.Unmarshal(fileContent(path), &sbom)
	return &sbom
}

func fileToContainerProfile(path string) v1beta1.ContainerProfile {
	ap := v1beta1.ContainerProfile{}
	_ = json.Unmarshal(fileContent(path), &ap)
	return ap
}

func TestScanService_NginxTest(t *testing.T) {
	imageSlug := "docker.io-library-nginx-1.14.1-3dc228"
	slug := "replicaset-nginx-75f48cbc54-nginx-10dc-2a65"
	ctx := context.TODO()
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter, terminate, err := v1.NewGrypeAdapterFixedDB()
	if errors.Is(err, v1.ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
	require.NoError(t, err)
	defer terminate()
	storageCP := repositories.NewMemoryStorage(false, false)
	storageSBOM := repositories.NewMemoryStorage(false, false)
	storageCVE := repositories.NewMemoryStorage(false, false)
	platform := adapters.NewMockPlatform(false, nil)
	relevancyProvider := v1.NewContainerProfileAdapter(storageCP)
	s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, platform, relevancyProvider, true, false, true, false, false)
	s.Ready(ctx)
	workload := domain.ScanCommand{
		Args: map[string]interface{}{
			domain.ArgsName:      "replicaset-nginx-75f48cbc54-nginx-714a-83bf",
			domain.ArgsNamespace: "default",
		},
		Wlid: "wlid://cluster-minikube/namespace-default/deployment-nginx",
	}
	ctx, err = s.ValidateScanCP(ctx, workload)
	require.NoError(t, err)
	sbom := domain.SBOM{
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:      "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			helpersv1.ImageTagMetadataKey:     "nginx",
			helpersv1.ResourceSizeMetadataKey: "3896210",
			helpersv1.StatusMetadataKey:       helpersv1.Learning,
		},
		Labels: map[string]string{
			helpersv1.ImageIDMetadataKey:   "docker-io-library-nginx-sha256-04ba374043ccd2fc5c593885c0eacdde",
			helpersv1.ImageNameMetadataKey: "docker-io-library-nginx",
		},
		Name:               imageSlug,
		Content:            fileToSyftDocument("../../adapters/v1/testdata/nginx-sbom.json"),
		SBOMCreatorVersion: sbomAdapter.Version(),
	}
	err = storageSBOM.StoreSBOM(ctx, sbom, false)
	require.NoError(t, err)
	ap := fileToContainerProfile("../../adapters/v1/testdata/nginx-ap.json")
	err = storageCP.StoreContainerProfile(ctx, ap)
	require.NoError(t, err)
	err = s.ScanCP(ctx)
	require.NoError(t, err)
	cvep, err := storageCVE.GetCVE(ctx, slug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx))
	require.NoError(t, err)
	assert.NotNil(t, cvep.Content)
}

func TestScanService_ValidateGenerateSBOM(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing imageSlug",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "with imageSlug",
			workload: domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false), repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), repositories.NewMemoryStorage(false, false), adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			_, err := s.ValidateGenerateSBOM(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanService_ValidateScanCP(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  error
	}{
		{
			name:     "missing args",
			workload: domain.ScanCommand{},
			wantErr:  domain.ErrMissingCpInfo,
		},
		{
			name: "non-string name and namespace",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName:      123,
					domain.ArgsNamespace: true,
				},
			},
			wantErr: domain.ErrMissingCpInfo,
		},
		{
			name: "non-string name only",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName:      123,
					domain.ArgsNamespace: "kube-system",
				},
			},
			wantErr: domain.ErrMissingCpInfo,
		},
		{
			name: "non-string namespace only",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName:      "daemonset-kube-proxy",
					domain.ArgsNamespace: true,
				},
			},
			wantErr: domain.ErrMissingCpInfo,
		},
		{
			name: "missing name only",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsNamespace: "kube-system",
				},
			},
			wantErr: domain.ErrMissingCpInfo,
		},
		{
			name: "missing namespace only",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName: "daemonset-kube-proxy",
				},
			},
			wantErr: domain.ErrMissingCpInfo,
		},
		{
			name: "with name and namespace",
			workload: domain.ScanCommand{
				Args: map[string]interface{}{
					domain.ArgsName:      "daemonset-kube-proxy",
					domain.ArgsNamespace: "kube-system",
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false), repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), repositories.NewMemoryStorage(false, false), adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			_, err := s.ValidateScanCP(context.TODO(), tt.workload)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScanService_ValidateScanCVE(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing Wlid",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "missing ImageHash",
			workload: domain.ScanCommand{
				Wlid: "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: true,
		},
		{
			name: "with Wlid and ImageHash",
			workload: domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
				Wlid:      "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false), repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), repositories.NewMemoryStorage(false, false), adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			_, err := s.ValidateScanCVE(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanService_ScanRegistry(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantErr         bool
		// wantReason, when non-empty, asserts the error ScanRegistry returns is a
		// *domain.ScanError carrying this scanfailure.Reason* value (see #540).
		wantReason string
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:       "timeout SBOM",
			timeout:    true,
			workload:   true,
			wantErr:    true,
			wantReason: scanfailure.ReasonSBOMIncomplete,
		},
		{
			name:            "toomanyrequests SBOM",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
			wantReason:      scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name:     "scan",
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			storage := repositories.NewMemoryStorage(false, false)
			s := NewScanService(sbomAdapter, storage, adapters.NewMockCVEAdapter(), storage, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			ctx := context.TODO()
			workload := domain.ScanCommand{
				ImageSlug:          "imageSlug",
				ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
			}
			workload.CredentialsList = []registry.AuthConfig{
				{
					Username: "test",
					Password: "test",
				},
				{
					RegistryToken: "test",
				},
				{
					Auth: "test",
				},
			}
			if tt.workload {
				var err error
				ctx, _ = s.ValidateScanRegistry(ctx, workload)
				require.NoError(t, err)
			}
			err := s.ScanRegistry(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanRegistry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, verr := s.ValidateScanRegistry(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, verr)
			}
			if tt.wantReason != "" {
				var scanErr *domain.ScanError
				require.ErrorAsf(t, err, &scanErr, "expected a *domain.ScanError, got %T: %v", err, err)
				assert.Equal(t, tt.wantReason, scanErr.Reason)
			}
			if tt.timeout {
				assert.ErrorIs(t, err, domain.ErrIncompleteSBOM)
			}
		})
	}
}

type mockSecurityExceptionRepo struct {
	exceptions        []sev1beta1.SecurityException
	clusterExceptions []sev1beta1.ClusterSecurityException
}

func (m *mockSecurityExceptionRepo) GetSecurityExceptions(ctx context.Context, namespace string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
	return m.exceptions, m.clusterExceptions, nil
}

func (m *mockSecurityExceptionRepo) GetWorkloadLabels(ctx context.Context, namespace, kind, name string) (map[string]string, error) {
	return nil, nil
}

func (m *mockSecurityExceptionRepo) GetNamespaceLabels(ctx context.Context, name string) (map[string]string, error) {
	return nil, nil
}

type fakeCVEScannerWithVuln struct {
	ports.CVEScanner
}

func (f *fakeCVEScannerWithVuln) DBVersion(context.Context) string { return "v1.0.0" }
func (f *fakeCVEScannerWithVuln) Ready(context.Context) bool       { return true }
func (f *fakeCVEScannerWithVuln) Version() string                  { return "v1.0.0" }
func (f *fakeCVEScannerWithVuln) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	return domain.CVEManifest{
		Name:               sbom.Name,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  "v1.0.0",
		CVEDBVersion:       "v1.0.0",
		Annotations:        sbom.Annotations,
		Labels:             sbom.Labels,
		Content: &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{
				{
					Vulnerability: v1beta1.Vulnerability{
						VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
							ID: "CVE-2023-9999",
						},
					},
				},
			},
		},
	}, nil
}

func TestScanService_ScanRegistry_StorageAndExceptions(t *testing.T) {
	t.Run("ScanRegistry applies exceptions and persists to storage", func(t *testing.T) {
		mockRepo := &mockSecurityExceptionRepo{
			exceptions: []sev1beta1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
					Spec: sev1beta1.SecurityExceptionSpec{
						Reason: "test exception",
						Vulnerabilities: []sev1beta1.VulnerabilityException{
							{
								Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-9999"},
								Status:        sev1beta1.VulnerabilityStatusNotAffected,
							},
						},
					},
				},
			},
		}
		mockPlatform := adapters.NewMockPlatform(false, mockRepo)
		storage := repositories.NewMemoryStorage(false, false)
		sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
		cveAdapter := &fakeCVEScannerWithVuln{}

		s := NewScanService(
			sbomAdapter,
			storage,
			cveAdapter,
			storage,
			mockPlatform,
			adapters.NewMockRelevancyAdapter(),
			true,  // storage enabled
			true,  // vexGeneration enabled
			true,  // sbomGeneration enabled
			false, // storeFilteredSbom
			false, // partialRelevancy
		)

		workload := domain.ScanCommand{
			ImageSlug:          "test-registry-image",
			ImageTagNormalized: "docker.io/library/test-registry-image:latest",
			JobID:              "job-123",
		}

		ctx, err := s.ValidateScanRegistry(context.Background(), workload)
		require.NoError(t, err)

		err = s.ScanRegistry(ctx)
		require.NoError(t, err)

		// Verify CVE is stored in storage with SecurityExceptions applied
		storedCVE, err := storage.GetCVE(ctx, workload.ImageSlug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx))
		require.NoError(t, err)
		assert.NotNil(t, storedCVE.Content)
		assert.Empty(t, storedCVE.Content.Matches, "matched vulnerability should be ignored by SecurityException")
		assert.Len(t, storedCVE.Content.IgnoredMatches, 1, "ignored match should be populated in stored CVE")
		assert.Equal(t, "CVE-2023-9999", storedCVE.Content.IgnoredMatches[0].Vulnerability.VulnerabilityMetadata.ID)
	})
}

func TestScanService_ValidateScanRegistry(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing imageID",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "with imageID",
			workload: domain.ScanCommand{
				ImageSlug:          "imageSlug",
				ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false), repositories.NewMemoryStorage(false, false), adapters.NewMockCVEAdapter(), repositories.NewMemoryStorage(false, false), adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			_, err := s.ValidateScanRegistry(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_generateScanID(t *testing.T) {
	type args struct {
		workload domain.ScanCommand
		version  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "generate scanID with imageHash",
			args: args{
				workload: domain.ScanCommand{
					ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
					ImageHash:          "sha256:6f9c1c5b5b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6b7b",
				},
			},
			want: "2d0ee020566e8ff66542c5cd9e324111731c6a49d237fea3bd880448dac1a37f",
		},
		{
			name: "generate scanID with instanceID",
			args: args{
				workload: domain.ScanCommand{
					InstanceID: "InstanceID",
				},
				version: "1.0.0",
			},
			want: "InstanceID-1-0-0",
		},
		{
			name: "generate scanID with instanceID without version",
			args: args{
				workload: domain.ScanCommand{
					InstanceID: "InstanceID",
				},
				version: "",
			},
			want: "InstanceID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateScanID(tt.args.workload, tt.args.version); got != tt.want {
				t.Errorf("generateScanID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_registryCredentialsFromCredentialsList(t *testing.T) {
	creds := []registry.AuthConfig{
		{
			ServerAddress: "quay.io",
			Auth:          "YXJtb3NlYyt0ZXN0cm9ib3QxOmR1bW15UGFzc3dvcmQ=",
			Username:      "armosec+testrobot1",
			Password:      "dummyPassword",
		},
		{
			ServerAddress: "https://index.docker.io/v1/",
			Username:      "test_user",
			Password:      "dummyPassword",
			Email:         "test_user@gmail.com",
			Auth:          "dGVzdF91c2VyOmR1bW15UGFzc3dvcmQ=",
		},
		{
			ServerAddress: "quay.io",
			Auth:          "YXJtb3NlYyt0ZXN0cm9ib3QyOmR1bW15UGFzc3dvcmQxMTE=",
			Username:      "armosec+testrobot2",
			Password:      "dummyPassword111",
		},
		{
			// Mirrors a .dockerconfigjson entry produced by reusing an existing
			// `docker login` (kubectl create secret generic --from-file=.dockerconfigjson=...):
			// only Auth is set, Username/Password are empty. See #611.
			ServerAddress: "registry.example.com",
			Auth:          base64.StdEncoding.EncodeToString([]byte("registryuser:registrypass")),
		},
	}
	registryCredentials := registryCredentialsFromCredentialsList(creds)
	assert.Equal(t, 4, len(registryCredentials))
	assert.Equal(t, "quay.io", registryCredentials[0].Authority)
	assert.Equal(t, "armosec+testrobot1", registryCredentials[0].Username)
	assert.Equal(t, "dummyPassword", registryCredentials[0].Password)
	assert.Equal(t, "index.docker.io", registryCredentials[1].Authority)
	assert.Equal(t, "test_user", registryCredentials[1].Username)
	assert.Equal(t, "dummyPassword", registryCredentials[1].Password)
	assert.Equal(t, "quay.io", registryCredentials[2].Authority)
	assert.Equal(t, "armosec+testrobot2", registryCredentials[2].Username)
	assert.Equal(t, "dummyPassword111", registryCredentials[2].Password)
	assert.Equal(t, "registry.example.com", registryCredentials[3].Authority)
	assert.Equal(t, "registryuser", registryCredentials[3].Username)
	assert.Equal(t, "registrypass", registryCredentials[3].Password)
}

func Test_credentialsFromAuth(t *testing.T) {
	tests := []struct {
		name         string
		auth         string
		wantUsername string
		wantPassword string
	}{
		{
			name:         "valid base64 user:pass",
			auth:         base64.StdEncoding.EncodeToString([]byte("user:pass")),
			wantUsername: "user",
			wantPassword: "pass",
		},
		{
			name:         "password containing a colon is preserved",
			auth:         base64.StdEncoding.EncodeToString([]byte("user:pass:word")),
			wantUsername: "user",
			wantPassword: "pass:word",
		},
		{
			name: "empty auth",
			auth: "",
		},
		{
			name: "not valid base64",
			auth: "not-base64!!!",
		},
		{
			name: "decodes but has no colon separator",
			auth: base64.StdEncoding.EncodeToString([]byte("userpass")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password := credentialsFromAuth(tt.auth)
			assert.Equal(t, tt.wantUsername, username)
			assert.Equal(t, tt.wantPassword, password)
		})
	}
}

func Test_parseAuthorityFromServerAddress(t *testing.T) {
	assert.Equal(t, "", parseAuthorityFromServerAddress(""))
	assert.Equal(t, "index.docker.io", parseAuthorityFromServerAddress("https://index.docker.io/v1/"))
	assert.Equal(t, "quay.io", parseAuthorityFromServerAddress("quay.io"))
	assert.Equal(t, "x.quay.io", parseAuthorityFromServerAddress("https://x.quay.io"))
	assert.Equal(t, "europe-docker.pkg.dev", parseAuthorityFromServerAddress("europe-docker.pkg.dev/xxx/xxx"))
}

func Test_filterSBOM(t *testing.T) {
	nginxSBOM := domain.SBOM{
		Name: "nginx-sbom",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			helpersv1.ImageTagMetadataKey: "nginx:1.14.1",
			helpersv1.StatusMetadataKey:   helpersv1.Learning,
		},
		Content: fileToSyftDocument("../../adapters/v1/testdata/nginx-sbom.json"),
	}
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(
		"apiVersion-apps/v1/namespace-default/kind-Deployment/name-nginx/containerName-nginx",
	)
	require.NoError(t, err)
	labels := map[string]string{
		helpersv1.ContainerNameMetadataKey: "nginx",
	}
	wlid := "wlid://cluster-test/namespace-default/deployment-nginx"

	type args struct {
		sbom          domain.SBOM
		instanceID    instanceidhandler.IInstanceID
		wlid          string
		relevantFiles mapset.Set[string]
		labels        map[string]string
		completion    string
	}
	tests := []struct {
		name    string
		args    args
		want    func(*testing.T, domain.SBOM)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "empty relevantFiles produces empty filtered content",
			args: args{
				sbom:          nginxSBOM,
				instanceID:    instanceID,
				wlid:          wlid,
				relevantFiles: mapset.NewSet[string](),
				labels:        labels,
				completion:    helpersv1.Full,
			},
			want: func(t *testing.T, got domain.SBOM) {
				assert.Empty(t, got.Content.Files)
				assert.Empty(t, got.Content.Artifacts)
				assert.Empty(t, got.Content.ArtifactRelationships)
			},
			wantErr: assert.NoError,
		},
		{
			name: "direct file match includes owning artifact",
			args: args{
				sbom:          nginxSBOM,
				instanceID:    instanceID,
				wlid:          wlid,
				relevantFiles: mapset.NewSet[string]("/etc/nginx/nginx.conf"),
				labels:        labels,
				completion:    helpersv1.Full,
			},
			want: func(t *testing.T, got domain.SBOM) {
				require.Len(t, got.Content.Files, 1)
				assert.Equal(t, "/etc/nginx/nginx.conf", got.Content.Files[0].Location.RealPath)
				// nginx.conf belongs to the nginx package; the relationship traversal
				// also pulls in nginx's transitive dependencies (libc6, openssl, etc.)
				assert.NotEmpty(t, got.Content.Artifacts)
				var artifactNames []string
				for _, a := range got.Content.Artifacts {
					artifactNames = append(artifactNames, a.Name)
				}
				assert.Contains(t, artifactNames, "nginx")
				assert.NotEmpty(t, got.Content.ArtifactRelationships)
			},
			wantErr: assert.NoError,
		},
		{
			// DynamicIdentifier (⋯, U+22EF) acts as a single-segment wildcard.
			// "/etc/nginx/⋯" matches all direct children of /etc/nginx/.
			name: "DynamicIdentifier matches multiple files and pulls in nginx artifact",
			args: args{
				sbom:          nginxSBOM,
				instanceID:    instanceID,
				wlid:          wlid,
				relevantFiles: mapset.NewSet[string]("/etc/nginx/" + dynamicpathdetector.DynamicIdentifier),
				labels:        labels,
				completion:    helpersv1.Full,
			},
			want: func(t *testing.T, got domain.SBOM) {
				// nginx-sbom has 8 files directly under /etc/nginx/
				assert.Equal(t, 8, len(got.Content.Files), "expected all /etc/nginx/* files to match")
				var artifactNames []string
				for _, a := range got.Content.Artifacts {
					artifactNames = append(artifactNames, a.Name)
				}
				assert.Contains(t, artifactNames, "nginx")
				assert.NotEmpty(t, got.Content.ArtifactRelationships)
			},
			wantErr: assert.NoError,
		},
		{
			name: "non-matching relevantFiles produces empty content",
			args: args{
				sbom:          nginxSBOM,
				instanceID:    instanceID,
				wlid:          wlid,
				relevantFiles: mapset.NewSet[string]("/nonexistent/path/file.txt"),
				labels:        labels,
				completion:    helpersv1.Full,
			},
			want: func(t *testing.T, got domain.SBOM) {
				assert.Empty(t, got.Content.Files)
				assert.Empty(t, got.Content.Artifacts)
				assert.Empty(t, got.Content.ArtifactRelationships)
			},
			wantErr: assert.NoError,
		},
		{
			name: "metadata annotations and labels are propagated correctly",
			args: args{
				sbom:          nginxSBOM,
				instanceID:    instanceID,
				wlid:          wlid,
				relevantFiles: mapset.NewSet[string](),
				labels:        labels,
				completion:    helpersv1.Full,
			},
			want: func(t *testing.T, got domain.SBOM) {
				assert.Equal(t, helpersv1.Full, got.Annotations[helpersv1.CompletionMetadataKey])
				assert.Equal(t, wlid, got.Annotations[helpersv1.WlidMetadataKey])
				assert.Equal(t, nginxSBOM.Annotations[helpersv1.ImageIDMetadataKey], got.Annotations[helpersv1.ImageIDMetadataKey])
				assert.Equal(t, "nginx", got.Annotations[helpersv1.ContainerNameMetadataKey])
				assert.Equal(t, helpersv1.ContainerArtifactType, got.Labels[helpersv1.ArtifactTypeMetadataKey])
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterSBOM(tt.args.sbom, tt.args.instanceID, tt.args.wlid, tt.args.relevantFiles, tt.args.labels, tt.args.completion)
			if !tt.wantErr(t, err, fmt.Sprintf("filterSBOM(%v, %v, %v, %v, %v, %v)", tt.args.sbom, tt.args.instanceID, tt.args.wlid, tt.args.relevantFiles, tt.args.labels, tt.args.completion)) {
				return
			}
			tt.want(t, got)
		})
	}
}

func BenchmarkFilterSBOM(b *testing.B) {
	nginxSBOM := domain.SBOM{
		Name: "nginx-sbom",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			helpersv1.ImageTagMetadataKey: "nginx:1.14.1",
			helpersv1.StatusMetadataKey:   helpersv1.Learning,
		},
		Content: fileToSyftDocument("../../adapters/v1/testdata/nginx-sbom.json"),
	}
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(
		"apiVersion-apps/v1/namespace-default/kind-Deployment/name-nginx/containerName-nginx",
	)
	require.NoError(b, err)
	labels := map[string]string{
		helpersv1.ContainerNameMetadataKey: "nginx",
	}
	wlid := "wlid://cluster-test/namespace-default/deployment-nginx"

	for _, dynamicPathCount := range []int{10, 100, 1000} {
		dynamicPathCount := dynamicPathCount
		b.Run(fmt.Sprintf("dynamicPaths=%d", dynamicPathCount), func(b *testing.B) {
			relevantFiles := mapset.NewSet[string]()
			for i := 0; i < dynamicPathCount; i++ {
				relevantFiles.Add(fmt.Sprintf("/var/lib/%s/segment-%d/data", dynamicpathdetector.DynamicIdentifier, i))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := filterSBOM(nginxSBOM, instanceID, wlid, relevantFiles, labels, helpersv1.Full)
				require.NoError(b, err)
			}
		})
	}
}

func TestOptionsFromWorkload(t *testing.T) {
	tests := []struct {
		name                string
		args                map[string]interface{}
		wantInsecureUseHTTP bool
		wantInsecureSkipTLS bool
		wantPlatform        string
	}{
		{
			name: "platform string is applied",
			args: map[string]interface{}{
				domain.ArgsPlatform: "linux/arm64",
			},
			wantPlatform: "linux/arm64",
		},
		{
			name: "bare arch platform string is passed through as-is",
			args: map[string]interface{}{
				domain.ArgsPlatform: "arm64",
			},
			wantPlatform: "arm64",
		},
		{
			name: "non-string platform value is ignored without panic",
			args: map[string]interface{}{
				domain.ArgsPlatform: float64(1),
			},
			wantPlatform: "",
		},
		{
			name:         "missing platform key defaults to empty (pod-less scans resolve whatever the manifest provides)",
			args:         map[string]interface{}{},
			wantPlatform: "",
		},
		{
			name: "bool true values are applied",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       true,
				domain.AttributeSkipTLSVerify: true,
			},
			wantInsecureUseHTTP: true,
			wantInsecureSkipTLS: true,
		},
		{
			name: "bool false values are applied",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       false,
				domain.AttributeSkipTLSVerify: false,
			},
			wantInsecureUseHTTP: false,
			wantInsecureSkipTLS: false,
		},
		{
			name: "string value is ignored without panic",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       "true",
				domain.AttributeSkipTLSVerify: "true",
			},
			wantInsecureUseHTTP: false,
			wantInsecureSkipTLS: false,
		},
		{
			name: "numeric value is ignored without panic",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       float64(1),
				domain.AttributeSkipTLSVerify: float64(1),
			},
			wantInsecureUseHTTP: false,
			wantInsecureSkipTLS: false,
		},
		{
			name: "nil value is ignored without panic",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       nil,
				domain.AttributeSkipTLSVerify: nil,
			},
			wantInsecureUseHTTP: false,
			wantInsecureSkipTLS: false,
		},
		{
			name:                "missing keys default to false",
			args:                map[string]interface{}{},
			wantInsecureUseHTTP: false,
			wantInsecureSkipTLS: false,
		},
		{
			name: "extra unrelated keys are ignored",
			args: map[string]interface{}{
				domain.AttributeUseHTTP:       true,
				domain.AttributeSkipTLSVerify: false,
				"some.other.attribute":        "noise",
			},
			wantInsecureUseHTTP: true,
			wantInsecureSkipTLS: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload := domain.ScanCommand{
				ImageSlug: "test-image-slug",
				Args:      tt.args,
			}
			got := optionsFromWorkload(context.Background(), workload)
			assert.Equal(t, tt.wantInsecureUseHTTP, got.InsecureUseHTTP,
				"InsecureUseHTTP mismatch for args: %v", tt.args)
			assert.Equal(t, tt.wantInsecureSkipTLS, got.InsecureSkipTLSVerify,
				"InsecureSkipTLSVerify mismatch for args: %v", tt.args)
			assert.Equal(t, tt.wantPlatform, got.Platform,
				"Platform mismatch for args: %v", tt.args)
		})
	}
}

type mockSBOMRepository struct {
	ports.SBOMRepository
	getSBOMSBOM  domain.SBOM
	getSBOMErr   error
	deleteErr    error
	deleteCalled bool
}

func (m *mockSBOMRepository) GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	return m.getSBOMSBOM, m.getSBOMErr
}

func (m *mockSBOMRepository) DeleteSBOM(ctx context.Context, name string) error {
	m.deleteCalled = true
	return m.deleteErr
}

func TestScanService_getSBOM_Outdated(t *testing.T) {
	tests := []struct {
		name       string
		sbom       domain.SBOM
		getErr     error
		deleteErr  error
		wantDelete bool
		wantSBOM   domain.SBOM
		wantErr    error
	}{
		{
			name: "outdated, too large, delete succeeds",
			sbom: domain.SBOM{
				Status:  helpersv1.TooLarge,
				Content: &v1beta1.SyftDocument{},
			},
			getErr:     domain.ErrOutdatedSBOM,
			deleteErr:  nil,
			wantDelete: true,
			wantSBOM:   domain.SBOM{},
			wantErr:    nil,
		},
		{
			name: "outdated, too large, delete fails",
			sbom: domain.SBOM{
				Status:  helpersv1.TooLarge,
				Content: &v1beta1.SyftDocument{},
			},
			getErr:     domain.ErrOutdatedSBOM,
			deleteErr:  fmt.Errorf("delete error"),
			wantDelete: true,
			wantSBOM:   domain.SBOM{},
			wantErr:    nil,
		},
		{
			name: "outdated, not too large, delete not called",
			sbom: domain.SBOM{
				Status:  "",
				Content: &v1beta1.SyftDocument{},
			},
			getErr:     domain.ErrOutdatedSBOM,
			deleteErr:  nil,
			wantDelete: false,
			wantSBOM:   domain.SBOM{},
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSBOMRepository{
				getSBOMSBOM: tt.sbom,
				getSBOMErr:  tt.getErr,
				deleteErr:   tt.deleteErr,
			}
			s := &ScanService{
				sbomRepository: repo,
			}
			gotSBOM, err := s.getSBOM(context.Background(), "test-sbom", "v1.0.0")
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantSBOM, gotSBOM)
			assert.Equal(t, tt.wantDelete, repo.deleteCalled)
		})
	}
}

// recordingPlatform implements ports.Platform for tests: it returns a configurable exception
// set (or error) and captures every manifest passed to SubmitCVE so cache-hit vs cache-miss
// telemetry can be asserted.
type recordingPlatform struct {
	exceptions       domain.CVEExceptions
	getExceptionsErr error
	submitted        []domain.CVEManifest
}

var _ ports.Platform = (*recordingPlatform)(nil)

func (p *recordingPlatform) GetCVEExceptions(context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	return p.exceptions, domain.ExceptionStats{}, p.getExceptionsErr
}

func (p *recordingPlatform) SubmitCVE(_ context.Context, cve domain.CVEManifest, _ domain.CVEManifest) error {
	p.submitted = append(p.submitted, cve)
	return nil
}

func (p *recordingPlatform) ReportError(context.Context, error) error { return nil }
func (p *recordingPlatform) ReportScanFailure(context.Context, scanfailure.ScanFailureCase, string, error) error {
	return nil
}
func (p *recordingPlatform) SendStatus(context.Context, int) error { return nil }

// countingCVERepository wraps a CVERepository and counts StoreCVE calls, so tests can assert a
// cached manifest was (or wasn't) rewritten without depending on the stored content alone.
type countingCVERepository struct {
	ports.CVERepository
	storeCVECalls int
}

func (c *countingCVERepository) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	c.storeCVECalls++
	return c.CVERepository.StoreCVE(ctx, cve, withRelevancy)
}

// fakeCVEScanner is a CVEScanner whose ScanSBOM output is fully controlled, used to exercise the
// cache-miss path with a real vulnerability ID (the shared MockCVEAdapter emits an empty-ID match
// that no SecurityException can target).
type fakeCVEScanner struct{}

func (fakeCVEScanner) ScanSBOM(_ context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	return domain.CVEManifest{
		Name:               sbom.Name,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  "fake-cve",
		CVEDBVersion:       "fake-db",
		Content: &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
		},
	}, nil
}

func (fakeCVEScanner) Version() string                  { return "fake-cve" }
func (fakeCVEScanner) DBVersion(context.Context) string { return "fake-db" }
func (fakeCVEScanner) Ready(context.Context) bool       { return true }

func matchForTest(id string) v1beta1.Match {
	return v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: id}}}
}

func ignoredMatchForTest(id string) v1beta1.IgnoredMatch {
	return v1beta1.IgnoredMatch{
		Match:              matchForTest(id),
		AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: id}},
	}
}

func exceptionPolicyForTest(id string) domain.CVEExceptions {
	return domain.CVEExceptions{{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: id}},
	}}
}

// newScanCVETestService builds a ScanService over in-memory storage with a configurable platform
// and CVE repository/scanner, returning the service, the version strings needed to seed/read a
// CVE manifest, and a validated context.
func newScanCVETestService(t *testing.T, platform ports.Platform, cveRepo ports.CVERepository, cveScanner ports.CVEScanner) (*ScanService, string, string, string, context.Context) {
	return newScanCVETestServiceVEX(t, platform, cveRepo, cveScanner, false)
}

func newScanCVETestServiceVEX(t *testing.T, platform ports.Platform, cveRepo ports.CVERepository, cveScanner ports.CVEScanner, vexGeneration bool) (*ScanService, string, string, string, context.Context) {
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	if cveScanner == nil {
		cveScanner = adapters.NewMockCVEAdapter()
	}
	s := NewScanService(sbomAdapter, repositories.NewMemoryStorage(false, false), cveScanner, cveRepo, platform, adapters.NewMockRelevancyAdapter(), true, vexGeneration, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)
	workload := domain.ScanCommand{
		ImageSlug:     "imageSlug",
		ContainerName: "kube-proxy",
		ImageHash:     "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
		Wlid:          "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
	}
	var err error
	ctx, err = s.ValidateScanCVE(ctx, workload)
	require.NoError(t, err)
	return s, sbomAdapter.Version(), cveScanner.Version(), cveScanner.DBVersion(ctx), ctx
}

func seedCachedCVEManifest(t *testing.T, repo ports.CVERepository, name, sbomCreatorVersion, cveScannerVersion, cveDBVersion string, ctx context.Context, content *v1beta1.GrypeDocument) {
	require.NoError(t, repo.StoreCVE(ctx, domain.CVEManifest{
		Name:               name,
		SBOMCreatorVersion: sbomCreatorVersion,
		CVEScannerVersion:  cveScannerVersion,
		CVEDBVersion:       cveDBVersion,
		Content:            content,
	}, false))
}

func matchIDs(matches []v1beta1.Match) []string {
	var ids []string
	for _, m := range matches {
		ids = append(ids, m.Vulnerability.ID)
	}
	return ids
}

// TestScanService_ScanCVE_CacheHit_DeletedExceptionRestoresSuppressedMatch is a regression test
// for the cached-manifest poisoning bug: deleting a SecurityException must un-suppress the
// finding on the next cache hit, and the backend must receive the unfiltered manifest.
func TestScanService_ScanCVE_CacheHit_DeletedExceptionRestoresSuppressedMatch(t *testing.T) {
	platform := &recordingPlatform{}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.NotNil(t, stored.Content)
	assert.Contains(t, matchIDs(stored.Content.Matches), "CVE-A", "deleted exception must restore the suppressed match")
	assert.Len(t, stored.Content.IgnoredMatches, 0)

	require.Len(t, platform.submitted, 1, "cache hit must still submit the manifest to the backend")
	assert.Contains(t, matchIDs(platform.submitted[0].Content.Matches), "CVE-A", "backend must receive the unfiltered manifest on a cache hit")
}

func TestScanService_ScanCVE_CacheHit_AddedExceptionSuppresses(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1)
	assert.Equal(t, "CVE-A", stored.Content.IgnoredMatches[0].Match.Vulnerability.ID)
}

func TestScanService_ScanCVE_CacheHit_UnchangedExceptionSkipsRewrite(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	inner := repositories.NewMemoryStorage(false, false)
	counting := &countingCVERepository{CVERepository: inner}
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, counting, nil)
	seedCachedCVEManifest(t, inner, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	assert.Zero(t, counting.storeCVECalls, "an unchanged exception set must not rewrite the cached manifest")
	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1)
	assert.Equal(t, "CVE-A", stored.Content.IgnoredMatches[0].Match.Vulnerability.ID)
}

func TestScanService_ScanCVE_CacheHit_ExceptionFetchFailureDoesNotWipe(t *testing.T) {
	platform := &recordingPlatform{getExceptionsErr: errors.New("backend unreachable")}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1, "a failed exception fetch must not wipe filtering from the stored manifest")
	assert.Equal(t, "CVE-A", stored.Content.IgnoredMatches[0].Match.Vulnerability.ID)
}

// TestScanService_ScanCVE_CacheHit_ExpiredOnFixRestoresFixedMatch is the reproduction matthyx
// provided during review: an ExpiredOnFix policy suppresses only the matches of a CVE whose
// Fix.State != "fixed". When one CVE hits two packages with different fix states, the ignored-ID
// set stays identical while the ignored-match set changes, so change detection must be keyed by
// match identity, not CVE ID.
func TestScanService_ScanCVE_CacheHit_ExpiredOnFixRestoresFixedMatch(t *testing.T) {
	fixedMatch := matchForTest("CVE-X")
	fixedMatch.Artifact = v1beta1.GrypePackage{Name: "pkgA", Version: "1.0.0"}
	fixedMatch.Vulnerability.Fix = v1beta1.Fix{State: "fixed", Versions: []string{"1.0.1"}}

	unfixedMatch := matchForTest("CVE-X")
	unfixedMatch.Artifact = v1beta1.GrypePackage{Name: "pkgB", Version: "2.0.0"}
	unfixedMatch.Vulnerability.Fix = v1beta1.Fix{State: "not-fixed"}

	expiredOnFix := true
	platform := &recordingPlatform{exceptions: domain.CVEExceptions{{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-X"}},
		ExpiredOnFix:          &expiredOnFix,
	}}}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)

	// cached: both matches suppressed by the earlier, wider policy (no ExpiredOnFix)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		IgnoredMatches: []v1beta1.IgnoredMatch{
			{Match: fixedMatch, AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-X"}}},
			{Match: unfixedMatch, AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-X"}}},
		},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.Matches, 1, "pkgA (fixed) must be restored into Matches")
	assert.Equal(t, "pkgA", stored.Content.Matches[0].Artifact.Name)
	require.Len(t, stored.Content.IgnoredMatches, 1)
	assert.Equal(t, "pkgB", stored.Content.IgnoredMatches[0].Match.Artifact.Name)
}

// TestScanService_ScanCVE_CacheHit_ExpiredOnFixWideningPersistsSuppression is the mirror case:
// widening the exception (dropping ExpiredOnFix) must suppress the previously-visible fixed match.
func TestScanService_ScanCVE_CacheHit_ExpiredOnFixWideningPersistsSuppression(t *testing.T) {
	fixedMatch := matchForTest("CVE-X")
	fixedMatch.Artifact = v1beta1.GrypePackage{Name: "pkgA", Version: "1.0.0"}
	fixedMatch.Vulnerability.Fix = v1beta1.Fix{State: "fixed", Versions: []string{"1.0.1"}}

	unfixedMatch := matchForTest("CVE-X")
	unfixedMatch.Artifact = v1beta1.GrypePackage{Name: "pkgB", Version: "2.0.0"}
	unfixedMatch.Vulnerability.Fix = v1beta1.Fix{State: "not-fixed"}

	// new, wider policy: no ExpiredOnFix → both pkgA and pkgB suppressed
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-X")}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)

	// cached: only pkgB was suppressed under the earlier ExpiredOnFix policy
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{fixedMatch},
		IgnoredMatches: []v1beta1.IgnoredMatch{
			{Match: unfixedMatch, AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-X"}}},
		},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	assert.Empty(t, stored.Content.Matches, "widening the exception must suppress pkgA too")
	require.Len(t, stored.Content.IgnoredMatches, 2)
}

// TestScanService_ScanCVE_CacheHit_DegradedFetchDoesNotPersistRemoval verifies Blocker 1: a
// transient SecurityException CRD list failure (ErrExceptionsDegraded, partial set) must not be
// mistaken for an exception deletion and wipe suppression from the stored manifest.
func TestScanService_ScanCVE_CacheHit_DegradedFetchDoesNotPersistRemoval(t *testing.T) {
	platform := &recordingPlatform{
		exceptions:       domain.CVEExceptions{}, // partial set: CVE-A exception missing (CRD list failed)
		getExceptionsErr: domain.ErrExceptionsDegraded,
	}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1, "a degraded fetch must not persist an apparent removal")
	assert.Equal(t, "CVE-A", stored.Content.IgnoredMatches[0].Match.Vulnerability.ID)
}

// TestScanService_ScanCVE_CacheHit_DegradedFetchPersistsAddition verifies that a purely additive
// change is persisted even when the exception set is incomplete.
func TestScanService_ScanCVE_CacheHit_DegradedFetchPersistsAddition(t *testing.T) {
	platform := &recordingPlatform{
		exceptions:       exceptionPolicyForTest("CVE-A"), // partial set still includes CVE-A
		getExceptionsErr: domain.ErrExceptionsDegraded,
	}
	repo := repositories.NewMemoryStorage(false, false)
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestService(t, platform, repo, nil)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1, "a purely additive change must be persisted even when degraded")
	assert.Equal(t, "CVE-A", stored.Content.IgnoredMatches[0].Match.Vulnerability.ID)
}

// TestScanService_ScanCVE_CacheMiss_UnfilteredToBackend guards the primary path: a fresh scan
// stores the exception-filtered manifest but submits the unfiltered original to the backend.
func TestScanService_ScanCVE_CacheMiss_UnfilteredToBackend(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := repositories.NewMemoryStorage(false, false)
	s, _, _, _, ctx := newScanCVETestService(t, platform, repo, fakeCVEScanner{})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1)

	require.Len(t, platform.submitted, 1)
	assert.Contains(t, matchIDs(platform.submitted[0].Content.Matches), "CVE-A", "backend must receive the unfiltered manifest on a cache miss")
}

// TestScanService_ScanCP_CacheHit_DeletedExceptionRestoresSuppressedMatch is the ScanCP mirror of
// the ScanCVE regression test, run with vexGeneration enabled so the StoreVEX path is exercised.
// The manifest handed to StoreVEX is the same object passed to SubmitCVE (scan.go), so the
// unfiltered submission assertion covers the VEX consequence transitively; that VEX statements
// are built from cve.Content.Matches (i.e. the restored manifest) is asserted directly by
// TestAPIServerStore_storeVEX (repositories/apiserver_test.go).
func TestScanService_ScanCP_CacheHit_DeletedExceptionRestoresSuppressedMatch(t *testing.T) {
	wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
	imageID := "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	imageTag := "k8s.gcr.io/kube-proxy:v1.24.3"
	// the full CVE manifest is keyed by the image slug ScanCP computes itself
	slug, err := names.ImageInfoToSlug(tools.NormalizeReference(imageTag), imageID)
	require.NoError(t, err)

	platform := &recordingPlatform{}
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter := adapters.NewMockCVEAdapter()
	storageCP := repositories.NewMemoryStorage(false, false)
	storageSBOM := repositories.NewMemoryStorage(false, false)
	storageCVE := repositories.NewMemoryStorage(false, false)
	s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, platform, v1.NewContainerProfileAdapter(storageCP), true, true, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)

	workload := domain.ScanCommand{
		Args: map[string]interface{}{
			domain.ArgsName:      "daemonset-kube-proxy",
			domain.ArgsNamespace: "kube-system",
		},
		Wlid: wlid,
	}
	ctx, err = s.ValidateScanCP(ctx, workload)
	require.NoError(t, err)

	ap := v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "daemonset-kube-proxy",
			Namespace: "kube-system",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-kube-system/kind-DaemonSet/name-kube-proxy/containerName-kube-proxy",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       wlid,
			},
			Labels: map[string]string{"foo": "bar"},
		},
		Spec: v1beta1.ContainerProfileSpec{
			ImageID:  imageID,
			ImageTag: imageTag,
		},
	}
	require.NoError(t, storageCP.StoreContainerProfile(ctx, ap))

	seedCachedCVEManifest(t, storageCVE, slug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx), ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCP(ctx))

	stored, err := storageCVE.GetCVE(ctx, slug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx))
	require.NoError(t, err)
	require.NotNil(t, stored.Content)
	assert.Contains(t, matchIDs(stored.Content.Matches), "CVE-A", "deleted exception must restore the suppressed match on a ScanCP cache hit")
	assert.Len(t, stored.Content.IgnoredMatches, 0)

	require.Len(t, platform.submitted, 1, "ScanCP cache hit must still submit the manifest to the backend")
	assert.Contains(t, matchIDs(platform.submitted[0].Content.Matches), "CVE-A", "backend must receive the unfiltered manifest on a ScanCP cache hit")
}

// TestFilterSBOM_TransitiveClosure is a regression test for #514: filterSBOM used to walk
// ArtifactRelationships in exactly two fixed passes, which only ever caught relevant artifacts
// up to one hop past the direct file owner, and even that one hop depended on the order
// ArtifactRelationships happened to be in (Syft does not document or guarantee any particular
// order). This constructs a 3-level containment chain - file F is owned by pkg-A, pkg-A is
// contained in pkg-B, pkg-B is contained in pkg-C - with the relationships listed
// outermost-first (C->B, B->A, A->F), the ordering that reproduced the bug.
// RelevantFiles carries two kinds of placeholder. DynamicIdentifier ("⋯") is one segment,
// so those paths keep their segment count and the #448 bucket is right for them.
// WildcardIdentifier ("*") is zero or more segments, and the detector produces it by
// collapsing runs of "⋯", so "/a/⋯/⋯/b" reaches us as "/a/*/b". Those were not
// picked up as dynamic at all, so the file, its package and everything above it were dropped
// and the relevancy scan called a loaded package not relevant.
func TestFilterSBOM_WildcardRelevantPaths(t *testing.T) {
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(
		"apiVersion-apps/v1/namespace-default/kind-Deployment/name-probe/containerName-probe",
	)
	require.NoError(t, err)

	d := dynamicpathdetector.DynamicIdentifier
	w := dynamicpathdetector.WildcardIdentifier

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"one segment placeholder", "/usr/lib/" + d + "/mod.so", "/usr/lib/python3/mod.so", true},
		{"one segment placeholder cannot span two", "/usr/lib/" + d + "/mod.so", "/usr/lib/a/b/mod.so", false},
		{"wildcard spanning several segments", "/usr/lib/" + w + "/mod.so", "/usr/lib/a/b/mod.so", true},
		{"wildcard spanning none", "/usr/lib/" + w + "/mod.so", "/usr/lib/mod.so", true},
		{"trailing wildcard", "/usr/lib/" + w, "/usr/lib/a/b/c", true},
		{"both placeholders together", "/usr/lib/" + d + "/" + w + "/mod.so", "/usr/lib/a/b/c/mod.so", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := domain.SBOM{
				Content: &v1beta1.SyftDocument{
					Files: []v1beta1.SyftFile{
						{ID: "file-F", Location: v1beta1.Coordinates{RealPath: tt.path}},
					},
					Artifacts: []v1beta1.SyftPackage{
						{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-A", Name: "A"}},
					},
					ArtifactRelationships: []v1beta1.SyftRelationship{
						{Parent: "pkg-A", Child: "file-F", Type: "contains"},
					},
				},
			}

			relevantFiles := mapset.NewSet[string]()
			relevantFiles.Add(tt.pattern)

			filtered, err := filterSBOM(sbom, instanceID, "wlid://x", relevantFiles, map[string]string{}, helpersv1.Full)
			require.NoError(t, err)

			if !tt.want {
				assert.Empty(t, filtered.Content.Files, "%q must not match %q", tt.pattern, tt.path)
				assert.Empty(t, filtered.Content.Artifacts)
				return
			}
			require.Len(t, filtered.Content.Files, 1, "the file matched by %q must survive the filter", tt.pattern)
			assert.Equal(t, tt.path, filtered.Content.Files[0].Location.RealPath)
			require.Len(t, filtered.Content.Artifacts, 1, "and so must the package that owns it")
			assert.Equal(t, "pkg-A", filtered.Content.Artifacts[0].ID)
		})
	}
}

func TestFilterSBOM_TransitiveClosure(t *testing.T) {
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(
		"apiVersion-apps/v1/namespace-default/kind-Deployment/name-probe/containerName-probe",
	)
	require.NoError(t, err)

	sbom := domain.SBOM{
		Content: &v1beta1.SyftDocument{
			Files: []v1beta1.SyftFile{
				{ID: "file-F", Location: v1beta1.Coordinates{RealPath: "/app/relevant.class"}},
			},
			Artifacts: []v1beta1.SyftPackage{
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-A", Name: "A"}},
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-B", Name: "B"}},
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-C", Name: "C"}},
			},
			ArtifactRelationships: []v1beta1.SyftRelationship{
				{Parent: "pkg-C", Child: "pkg-B", Type: "contains"},
				{Parent: "pkg-B", Child: "pkg-A", Type: "contains"},
				{Parent: "pkg-A", Child: "file-F", Type: "contains"},
			},
		},
	}

	relevantFiles := mapset.NewSet[string]()
	relevantFiles.Add("/app/relevant.class")

	filtered, err := filterSBOM(sbom, instanceID, "wlid://x", relevantFiles, map[string]string{}, helpersv1.Full)
	require.NoError(t, err)

	var gotIDs []string
	for _, a := range filtered.Content.Artifacts {
		gotIDs = append(gotIDs, a.ID)
	}
	assert.ElementsMatch(t, []string{"pkg-A", "pkg-B", "pkg-C"}, gotIDs,
		"every artifact that transitively contains a relevant file must be kept, regardless of relationship order")

	var gotRelationshipPairs []string
	for _, r := range filtered.Content.ArtifactRelationships {
		gotRelationshipPairs = append(gotRelationshipPairs, r.Parent+"->"+r.Child)
	}
	assert.ElementsMatch(t, []string{"pkg-A->file-F", "pkg-B->pkg-A", "pkg-C->pkg-B"}, gotRelationshipPairs)
}

// TestFilterSBOM_PreservesSourceRelationshipOrder is a regression test for CodeRabbit's
// review on #515: the BFS fix for #514 emitted relationships as it discovered them, but
// mapset's ToSlice() has no stable order, so with multiple relevant files the output order
// could vary between calls on the same input. filterSBOM must emit ArtifactRelationships in
// the same order they appear in sbom.Content.ArtifactRelationships, filtered down to the
// relevant ones - not in discovery order.
func TestFilterSBOM_PreservesSourceRelationshipOrder(t *testing.T) {
	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(
		"apiVersion-apps/v1/namespace-default/kind-Deployment/name-probe/containerName-probe",
	)
	require.NoError(t, err)

	// Two independent relevant files, each with its own 2-level chain, interleaved in the
	// source relationship list rather than grouped by file.
	sourceRelationships := []v1beta1.SyftRelationship{
		{Parent: "pkg-B1", Child: "pkg-A1", Type: "contains"},
		{Parent: "pkg-A2", Child: "file-F2", Type: "contains"},
		{Parent: "pkg-A1", Child: "file-F1", Type: "contains"},
		{Parent: "pkg-B2", Child: "pkg-A2", Type: "contains"},
	}

	sbom := domain.SBOM{
		Content: &v1beta1.SyftDocument{
			Files: []v1beta1.SyftFile{
				{ID: "file-F1", Location: v1beta1.Coordinates{RealPath: "/app/f1.class"}},
				{ID: "file-F2", Location: v1beta1.Coordinates{RealPath: "/app/f2.class"}},
			},
			Artifacts: []v1beta1.SyftPackage{
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-A1", Name: "A1"}},
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-B1", Name: "B1"}},
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-A2", Name: "A2"}},
				{PackageBasicData: v1beta1.PackageBasicData{ID: "pkg-B2", Name: "B2"}},
			},
			ArtifactRelationships: sourceRelationships,
		},
	}

	relevantFiles := mapset.NewSet[string]()
	relevantFiles.Add("/app/f1.class")
	relevantFiles.Add("/app/f2.class")

	filtered, err := filterSBOM(sbom, instanceID, "wlid://x", relevantFiles, map[string]string{}, helpersv1.Full)
	require.NoError(t, err)

	// Every source relationship is relevant here, so the filtered order must equal the
	// source order exactly - not just contain the same elements.
	require.Equal(t, sourceRelationships, filtered.Content.ArtifactRelationships,
		"filterSBOM must emit ArtifactRelationships in source order, not discovery order")
}

func TestScanService_ScanRegistry_RateLimitBackoff(t *testing.T) {
	imageID := "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	imageTag := "docker.io/library/nginx:1.25"
	slug, err := names.ImageInfoToSlug(tools.NormalizeReference(imageTag), imageID)
	require.NoError(t, err)

	platform := &recordingPlatform{}
	countingSBOM := &countingSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)}
	cveAdapter := adapters.NewMockCVEAdapter()
	s := NewScanService(countingSBOM, repositories.NewMemoryStorage(false, false), cveAdapter, repositories.NewMemoryStorage(false, false), platform, nil, false, false, true, false, false)

	// registryScanCommandToScanCommand never populates ImageHash, so this reflects what
	// ScanRegistry actually receives - not a workload-scan payload.
	workload := domain.ScanCommand{
		ImageTag:           imageTag,
		ImageTagNormalized: tools.NormalizeReference(imageTag),
		ImageSlug:          slug,
		JobID:              "job-registry",
	}
	ctx := enrichContext(context.TODO(), workload, s.Version())

	// Simulate a prior 429 rate limit recorded for this image
	key := rateLimitCacheKey(workload)
	s.tooManyRequests.Set(key, true, ttl)

	// ValidateScanRegistry must return ErrTooManyRequests
	_, valErr := s.ValidateScanRegistry(ctx, workload)
	assert.ErrorIs(t, valErr, domain.ErrTooManyRequests)

	// ScanRegistry execution path must also abort and return ErrTooManyRequests
	scanErr := s.ScanRegistry(ctx)
	assert.ErrorIs(t, scanErr, domain.ErrTooManyRequests)
	assert.Equal(t, 0, countingSBOM.calls, "ScanRegistry must not attempt CreateSBOM when rate limited")
}

func TestScanService_CrossFlowRateLimitBackoff(t *testing.T) {
	imageID := "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	imageTag := "k8s.gcr.io/kube-proxy:v1.24.3"
	normalizedTag := tools.NormalizeReference(imageTag)
	normalizedImageID := v1.NormalizeImageID(imageID, imageTag)
	slug, err := names.ImageInfoToSlug(normalizedTag, imageID)
	require.NoError(t, err)

	// Workload scans (ScanCVE/GenerateSBOM/ScanCP) receive a payload with ImageHash populated.
	workload := domain.ScanCommand{
		ImageHash:          normalizedImageID,
		ImageTag:           imageTag,
		ImageTagNormalized: normalizedTag,
		ImageSlug:          slug,
	}

	// Registry scans never populate ImageHash - registryScanCommandToScanCommand doesn't set
	// it, so this is what ScanRegistry actually receives for the same image. Using the same
	// workload struct for every flow (as this test used to) hid the bug: it never exercised
	// the ImageHash=="" case a real registry scan sends.
	registryWorkload := domain.ScanCommand{
		ImageTag:           imageTag,
		ImageTagNormalized: normalizedTag,
		ImageSlug:          slug,
	}

	require.Equal(t, rateLimitCacheKey(workload), rateLimitCacheKey(registryWorkload),
		"a workload scan and a registry scan for the same image must resolve to the same rate-limit cache key")

	key := rateLimitCacheKey(workload)

	platform := &recordingPlatform{}
	countingSBOM := &countingSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)}
	cveAdapter := adapters.NewMockCVEAdapter()
	s := NewScanService(countingSBOM, repositories.NewMemoryStorage(false, false), cveAdapter, repositories.NewMemoryStorage(false, false), platform, nil, false, false, true, false, false)

	// Record rate limit under canonical key
	s.tooManyRequests.Set(key, true, ttl)

	// All validation entry points must recognize the rate limit
	_, errValGen := s.ValidateGenerateSBOM(context.TODO(), workload)
	assert.ErrorIs(t, errValGen, domain.ErrTooManyRequests)

	_, errValCVE := s.ValidateScanCVE(context.TODO(), workload)
	assert.ErrorIs(t, errValCVE, domain.ErrTooManyRequests)

	_, errValReg := s.ValidateScanRegistry(context.TODO(), registryWorkload)
	assert.ErrorIs(t, errValReg, domain.ErrTooManyRequests)

	ctx := enrichContext(context.TODO(), workload, s.Version())
	registryCtx := enrichContext(context.TODO(), registryWorkload, s.Version())

	// Execution paths must also abort and return ErrTooManyRequests without calling CreateSBOM
	assert.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrTooManyRequests)
	assert.ErrorIs(t, s.ScanCVE(ctx), domain.ErrTooManyRequests)
	assert.ErrorIs(t, s.ScanRegistry(registryCtx), domain.ErrTooManyRequests)
	assert.Equal(t, 0, countingSBOM.calls, "No execution path should attempt CreateSBOM when rate limited")
}

func TestScanCVE_NoSBOMRegeneration_OnCacheHit(t *testing.T) {
	// Setup
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	storageSBOM := repositories.NewMemoryStorage(false, false)
	cveAdapter := adapters.NewMockCVEAdapter()
	storageCVE := repositories.NewMemoryStorage(false, false)
	platform := &recordingPlatform{}
	relevancy := adapters.NewMockRelevancyAdapter()
	service := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, platform, relevancy, true, true, true, false, false)

	slug := "wasteful-sbom-test"

	// Create a cached CVE
	cveAdapterDBVersion := cveAdapter.DBVersion(context.TODO())
	cacheCVE := domain.CVEManifest{
		Name:               slug,
		SBOMCreatorVersion: sbomAdapter.Version(),
		CVEScannerVersion:  cveAdapter.Version(),
		CVEDBVersion:       cveAdapterDBVersion,
		Content:            &v1beta1.GrypeDocument{},
		Labels: map[string]string{
			"kubevuln.kubescape.io/image-slug":         slug,
			"kubevuln.kubescape.io/sbom-creator":       sbomAdapter.Version(),
			"kubevuln.kubescape.io/cve-scanner":        cveAdapter.Version(),
			"kubevuln.kubescape.io/cve-scanner-db":     cveAdapterDBVersion,
			"kubevuln.kubescape.io/workload-name":      "my-workload",
			"kubevuln.kubescape.io/workload-namespace": "default",
			"kubevuln.kubescape.io/workload-kind":      "Deployment",
		},
	}
	require.NoError(t, storageCVE.StoreCVE(context.TODO(), cacheCVE, false))

	// No SBOM in storage! (cache miss for SBOM)

	// Context with Workload containing an InstanceID
	workload := domain.ScanCommand{
		ImageSlug:  slug,
		InstanceID: "some-instance-id", // triggers `workload.InstanceID != ""`
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)

	// Run ScanCVE
	err := service.ScanCVE(ctx)
	require.NoError(t, err)

	// Verify that CreateSBOM was NOT called.
	// We check if the storage now has the SBOM (which indicates it was generated).
	generatedSBOM, err := storageSBOM.GetSBOM(context.TODO(), slug, sbomAdapter.Version())

	// Since we no longer generate the SBOM wastefully, the storage should return an empty content
	require.NoError(t, err, "MemoryStorage returns a nil error on a cache miss")
	require.Nil(t, generatedSBOM.Content, "The generated SBOM should be nil since we avoided regenerating it wastefully")

}

// vexRecordingCVERepository records StoreVEX calls so a test can assert whether a VEX
// document was written, which the in-memory repository cannot show on its own: its StoreVEX
// is a no-op that keeps nothing.
type vexRecordingCVERepository struct {
	ports.CVERepository
	vexCalls []domain.CVEManifest
}

func (v *vexRecordingCVERepository) StoreVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	v.vexCalls = append(v.vexCalls, cve)
	return v.CVERepository.StoreVEX(ctx, cve, cvep, withRelevancy)
}

// TestScanService_ScanCVE_CacheMiss_GeneratesVEX is the core regression test for #557: ScanCVE
// had no StoreVEX call anywhere in its body, so an operator running with vexGeneration enabled
// got no VEX document from the plain per-container scan route at all.
func TestScanService_ScanCVE_CacheMiss_GeneratesVEX(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, _, _, _, ctx := newScanCVETestServiceVEX(t, platform, repo, fakeCVEScanner{}, true)

	require.NoError(t, s.ScanCVE(ctx))

	require.Len(t, repo.vexCalls, 1, "a fresh ScanCVE must generate a VEX document")
	require.NotNil(t, repo.vexCalls[0].Content)
	assert.Len(t, repo.vexCalls[0].Content.IgnoredMatches, 1,
		"the VEX document must be built from the exception-filtered manifest")
}

func TestScanService_ScanCVE_CacheMiss_NoVEXWhenDisabled(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, _, _, _, ctx := newScanCVETestServiceVEX(t, platform, repo, fakeCVEScanner{}, false)

	require.NoError(t, s.ScanCVE(ctx))

	assert.Empty(t, repo.vexCalls, "vexGeneration is off, so nothing should be written")
}

// A degraded exception fetch means the set is incomplete, so the document would assert fewer
// suppressions than the user configured. ScanCP already declines to publish in that case.
func TestScanService_ScanCVE_CacheMiss_DegradedFetchSkipsVEX(t *testing.T) {
	platform := &recordingPlatform{
		exceptions:       exceptionPolicyForTest("CVE-A"),
		getExceptionsErr: domain.ErrExceptionsDegraded,
	}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, _, _, _, ctx := newScanCVETestServiceVEX(t, platform, repo, fakeCVEScanner{}, true)

	require.NoError(t, s.ScanCVE(ctx))

	assert.Empty(t, repo.vexCalls, "an incomplete exception set must not produce a VEX document")
}

// On a cache hit that re-evaluates exceptions, the stored manifest changes, so the VEX document
// describing it has to change with it or the two disagree until the next cache miss.
func TestScanService_ScanCVE_CacheHit_ExceptionChangeUpdatesVEX(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestServiceVEX(t, platform, repo, nil, true)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	require.Len(t, repo.vexCalls, 1, "a changed ignored-match set must update the VEX document")
	require.NotNil(t, repo.vexCalls[0].Content)
	assert.Len(t, repo.vexCalls[0].Content.IgnoredMatches, 1)
}

func TestScanService_ScanCVE_CacheHit_UnchangedExceptionSkipsVEX(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestServiceVEX(t, platform, repo, nil, true)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches:        []v1beta1.Match{matchForTest("CVE-B")},
		IgnoredMatches: []v1beta1.IgnoredMatch{ignoredMatchForTest("CVE-A")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	assert.Empty(t, repo.vexCalls, "nothing changed, so the stored VEX document is still accurate")
}

// TestScanService_ScanRegistry_CacheHit_ExceptionChangeUpdatesVEX covers the second half of
// #557: ScanRegistry's cache-miss branch stored VEX but its cache-hit branch did not, even
// though the comment directly above that branch says StoreVEX runs there.
func TestScanService_ScanRegistry_CacheHit_ExceptionChangeUpdatesVEX(t *testing.T) {
	platform := &recordingPlatform{exceptions: exceptionPolicyForTest("CVE-A")}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter := adapters.NewMockCVEAdapter()
	s := NewScanService(sbomAdapter, repositories.NewMemoryStorage(false, false), cveAdapter, repo,
		platform, adapters.NewMockRelevancyAdapter(), true, true, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)

	workload := domain.ScanCommand{
		ImageSlug:          "imageSlug",
		ImageTagNormalized: "docker.io/library/test-registry-image:latest",
		JobID:              "job-123",
	}
	ctx, err := s.ValidateScanRegistry(ctx, workload)
	require.NoError(t, err)

	seedCachedCVEManifest(t, repo, "imageSlug", sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx), ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
	})

	require.NoError(t, s.ScanRegistry(ctx))

	require.Len(t, repo.vexCalls, 1, "a ScanRegistry cache hit that changes the ignored set must update the VEX document")
	require.NotNil(t, repo.vexCalls[0].Content)
	assert.Len(t, repo.vexCalls[0].Content.IgnoredMatches, 1)
}

// A degraded exception fetch must not publish a VEX document from a partial set on the
// registry cache-miss path either, matching how ScanCVE and ScanCP gate their own calls.
func TestScanService_ScanRegistry_CacheMiss_DegradedFetchSkipsVEX(t *testing.T) {
	platform := &recordingPlatform{
		exceptions:       exceptionPolicyForTest("CVE-A"),
		getExceptionsErr: domain.ErrExceptionsDegraded,
	}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter := adapters.NewMockCVEAdapter()
	s := NewScanService(sbomAdapter, repositories.NewMemoryStorage(false, false), cveAdapter, repo,
		platform, adapters.NewMockRelevancyAdapter(), true, true, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)

	ctx, err := s.ValidateScanRegistry(ctx, domain.ScanCommand{
		ImageSlug:          "imageSlug",
		ImageTagNormalized: "docker.io/library/test-registry-image:latest",
		JobID:              "job-123",
	})
	require.NoError(t, err)

	require.NoError(t, s.ScanRegistry(ctx))

	assert.Empty(t, repo.vexCalls, "an incomplete exception set must not produce a VEX document")
}

// A degraded exception fetch must not republish VEX on a cache hit either, even when the
// change is purely additive and the manifest itself is persisted. The manifest can safely
// take additions from a partial set; a published VEX document built from one understates
// which CVEs are suppressed.
func TestScanService_ScanCVE_CacheHit_DegradedAdditiveSkipsVEX(t *testing.T) {
	platform := &recordingPlatform{
		exceptions:       exceptionPolicyForTest("CVE-A"),
		getExceptionsErr: domain.ErrExceptionsDegraded,
	}
	repo := &vexRecordingCVERepository{CVERepository: repositories.NewMemoryStorage(false, false)}
	s, sbomVer, cveVer, cveDBVer, ctx := newScanCVETestServiceVEX(t, platform, repo, nil, true)
	seedCachedCVEManifest(t, repo, "imageSlug", sbomVer, cveVer, cveDBVer, ctx, &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")},
	})

	require.NoError(t, s.ScanCVE(ctx))

	stored, err := s.cveRepository.GetCVE(ctx, "imageSlug", s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
	require.NoError(t, err)
	require.Len(t, stored.Content.IgnoredMatches, 1, "the additive change is still persisted to the manifest")

	assert.Empty(t, repo.vexCalls, "but no VEX document is published from a partial exception set")
}

// getSBOM discards an SBOM that was rejected under limits which have since changed, so a
// rescan can admit an image the operator has just made room for. ScanRegistry called the
// repository directly and skipped that, so it kept serving a cached TooLarge verdict forever:
// raising maxImageSize had no effect on the registry path while it worked on every other one.
func TestScanService_ScanRegistry_StaleTooLargeSBOMIsRescanned(t *testing.T) {
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	repo := repositories.NewMemoryStorage(false, false)
	s := NewScanService(sbomAdapter, repo, adapters.NewMockCVEAdapter(), repo,
		&recordingPlatform{}, v1.NewContainerProfileAdapter(repositories.NewMemoryStorage(false, false)),
		true, false, true, false, false)
	ctx := context.TODO()
	s.Ready(ctx)

	ctx, err := s.ValidateScanRegistry(ctx, domain.ScanCommand{
		ImageSlug:          "imageSlug",
		ImageTagNormalized: "docker.io/library/nginx:latest",
	})
	require.NoError(t, err)

	// Stored when the image-size limit was 1 byte. The current limit differs, so this
	// verdict no longer reflects the configuration and must not be reused.
	require.NoError(t, repo.StoreSBOM(ctx, domain.SBOM{
		Name:               "imageSlug",
		SBOMCreatorVersion: sbomAdapter.Version(),
		Status:             helpersv1.TooLarge,
		Content:            &v1beta1.SyftDocument{},
		Annotations: map[string]string{
			domain.StatusReasonAnnotationKey: domain.ReasonImageTooLarge,
			domain.MaxImageSizeAnnotationKey: "1",
		},
	}, false))
	require.NotEqual(t, "1", fmt.Sprintf("%d", sbomAdapter.GetMaxImageSize()),
		"the test needs the current limit to differ from the stored one")

	require.NoError(t, s.ScanRegistry(ctx))

	stored, err := repo.GetSBOM(ctx, "imageSlug", sbomAdapter.Version())
	require.NoError(t, err)
	assert.NotEqual(t, helpersv1.TooLarge, stored.Status,
		"the stale TooLarge SBOM must be replaced by a fresh scan, not served again")
}

type blockingSBOMCreator struct {
	ports.SBOMCreator
	calls   int
	onStart func()
	mu      sync.Mutex
}

func (b *blockingSBOMCreator) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	if b.onStart != nil {
		b.onStart()
	}
	return b.SBOMCreator.CreateSBOM(ctx, name, imageID, imageTag, options)
}

// kubevuln_singleflight_hits_total is meant to count requests that singleflight spared
// from doing the work. res.Shared does not identify those: it means the result went to more
// than one caller, which is true of the leader as well, so a burst of N collapsing to one
// creation reported N deduplicated requests instead of N-1.
func TestScanService_SingleflightHitsCountOnlyDeduplicatedCallers(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	creator := &blockingSBOMCreator{
		SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false),
		onStart: func() {
			once.Do(func() { close(started) })
			<-release
		},
	}

	// storage off, so a caller that arrives late and starts its own round reaches CreateSBOM
	// rather than being served by the worker's storage re-check. That keeps "callers that
	// ran the work" equal to CreateSBOM calls, which is what the assertion below leans on.
	store := repositories.NewMemoryStorage(false, false)
	s := NewScanService(creator, store, adapters.NewMockCVEAdapter(), store, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)

	workload := domain.ScanCommand{
		ImageSlug:          "library-alpine-latest-1234567890ab",
		ImageTagNormalized: "library/alpine:latest",
		ImageHash:          "sha256:1234567890ab",
	}

	const callers = 5
	var startWg, wg sync.WaitGroup
	startWg.Add(callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startWg.Done()
			_, _, err := s.getOrCreateSBOM(context.TODO(), workload)
			assert.NoError(t, err)
		}()
	}
	startWg.Wait()
	<-started
	close(release)
	wg.Wait()

	// Every caller either did the work or was spared it, so the two must add up, whether or
	// not one of them was late enough to start a round of its own.
	creator.mu.Lock()
	ranTheWork := creator.calls
	creator.mu.Unlock()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	assert.Contains(t, w.Body.String(),
		fmt.Sprintf(`kubevuln_singleflight_hits_total{target="sbom_generation"} %d`, callers-ranTheWork),
		"the caller that did the work is not one of the callers it spared")
}

func TestScanService_SingleflightSBOMDeduplication(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	blockingCreator := &blockingSBOMCreator{
		SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false),
		onStart: func() {
			once.Do(func() {
				close(started)
			})
			<-release
		},
	}

	service := NewScanService(
		blockingCreator,
		repositories.NewMemoryStorage(false, false),
		adapters.NewMockCVEAdapter(),
		repositories.NewMemoryStorage(false, false),
		adapters.NewMockPlatform(false, nil),
		adapters.NewMockRelevancyAdapter(),
		true, false, true, false, false,
	)

	workload := domain.ScanCommand{
		ImageSlug:          "library/alpine:latest",
		ImageTagNormalized: "library/alpine:latest",
		ImageHash:          "sha256:1234567890",
	}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)

	const numGoroutines = 5
	var startWg sync.WaitGroup
	var wg sync.WaitGroup
	startWg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startWg.Done()
			_ = service.GenerateSBOM(ctx)
		}()
	}

	startWg.Wait() // ensure all 5 goroutines are running before unblocking singleflight worker
	<-started      // wait for singleflight worker to enter CreateSBOM
	close(release) // allow singleflight worker to finish
	wg.Wait()

	assert.Equal(t, 1, blockingCreator.calls, "CreateSBOM should be called exactly once for concurrent identical requests")
}
