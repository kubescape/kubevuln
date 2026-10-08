package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

type hostInventoryRoundTripper func(*http.Request) (*http.Response, error)

func (f hostInventoryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGetHostSBOMBoundedLookup(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		name := "lookup timeout is pending"
		if cancelParent {
			name = "parent cancellation is terminal"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := time.Now()
			requests := 0
			client, err := spdxv1beta1.NewForConfigAndClient(&rest.Config{Host: "https://storage.example"}, &http.Client{
				Transport: hostInventoryRoundTripper(func(req *http.Request) (*http.Response, error) {
					requests++
					require.Equal(t, http.MethodGet, req.Method)
					require.True(t, strings.HasSuffix(req.URL.Path, "/sbomsyfts/"+hostInventoryIdentifier("host-", "node.a")))
					deadline, ok := req.Context().Deadline()
					require.True(t, ok, "even the first lookup must have a deadline")
					require.False(t, deadline.Before(started.Add(30*time.Second)))
					require.False(t, deadline.After(time.Now().Add(30*time.Second)))
					if cancelParent {
						cancel()
					}
					// Exercise the real typed client's error wrapping without waiting
					// for the 30-second I/O deadline to elapse.
					return nil, context.DeadlineExceeded
				}),
			})
			require.NoError(t, err)
			repo := &APIServerStore{Namespace: "kubescape", StorageClient: client}
			_, err = repo.GetHostSBOM(ctx, "node.a")
			require.Equal(t, 1, requests)
			if cancelParent {
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, domain.ErrHostInventoryPending)
			} else {
				require.NoError(t, ctx.Err())
				require.ErrorIs(t, err, domain.ErrHostInventoryPending)
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
		})
	}
}

func TestHostInventoryIdentifierProducerGolden(t *testing.T) {
	for _, tc := range []struct{ node, base, hash string }{
		{"node.a", "node-a", "981e6a0debbb274ebadfb55c1047b758"},
		{"node-a", "node-a", "66570ff05a2074043084d4aca94293ef"},
		{strings.Repeat("a", 60) + "x", strings.Repeat("a", 30), "fc338f7335fe40ba62d16d6548471c30"},
		{strings.Repeat("a", 60) + "y", strings.Repeat("a", 30), "64246930759f9429a518679bde9d7ff1"},
	} {
		base := tc.base
		require.Equal(t, base+"-"+tc.hash, hostInventoryIdentifier("", tc.node))
		if len(base) > 25 {
			base = base[:25]
		}
		require.Equal(t, "host-"+base+"-"+tc.hash, hostInventoryIdentifier("host-", tc.node))
	}
}

func readyHostInventory() *v1beta1.SBOMSyft {
	return &v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{Name: hostInventoryIdentifier("host-", "node.a"), Namespace: "kubescape", UID: "inventory-uid", ResourceVersion: "42",
			Labels:      map[string]string{"kubescape.io/host": hostInventoryIdentifier("", "node.a"), "kubescape.io/node-name": hostInventoryIdentifier("", "node.a")},
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Learning}},
		Spec: v1beta1.SBOMSyftSpec{Metadata: v1beta1.SPDXMeta{Tool: v1beta1.ToolMeta{Name: "syft", Version: "v1.99.0"}}, Syft: v1beta1.SyftDocument{
			SyftSource: v1beta1.SyftSource{Type: "directory", Metadata: json.RawMessage(`{"path":"/host"}`)},
			Schema:     v1beta1.Schema{Version: "16.0.39"}, Distro: v1beta1.LinuxRelease{ID: "alpine", VersionID: "3.20"},
		}},
	}
}
func TestGetHostSBOMValidatedOwnedSnapshot(t *testing.T) {
	original := readyHostInventory()
	repo := NewFakeAPIServerStorage("kubescape", original)
	got, err := repo.GetHostSBOM(context.Background(), "node.a")
	require.NoError(t, err)
	require.Equal(t, "v1.99.0", got.SBOMCreatorVersion)
	require.Equal(t, "syft", got.SBOMCreatorName)
	require.Equal(t, "inventory-uid", got.Annotations[domain.HostInventoryUIDAnnotationKey])
	require.Equal(t, "42", got.Annotations[domain.HostInventoryResourceVersionAnnotationKey])
	got.Labels["changed"] = "yes"
	got.Content.Distro.ID = "mutated"
	got.Content.SyftSource.Metadata[0] = 'x'
	stored, err := repo.StorageClient.SBOMSyfts("kubescape").Get(context.Background(), original.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Empty(t, stored.Labels["changed"])
	require.Equal(t, "alpine", stored.Spec.Syft.Distro.ID)
	require.Equal(t, byte('{'), stored.Spec.Syft.SyftSource.Metadata[0])
	require.Empty(t, stored.Annotations[domain.HostInventoryUIDAnnotationKey])
}
func TestGetHostSBOMPendingAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*v1beta1.SBOMSyft)
		pending bool
	}{
		{"initializing", func(m *v1beta1.SBOMSyft) { m.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Initializing }, true},
		{"missing host label", func(m *v1beta1.SBOMSyft) { delete(m.Labels, "kubescape.io/host") }, false},
		{"wrong node label", func(m *v1beta1.SBOMSyft) { m.Labels["kubescape.io/node-name"] = "wrong" }, false},
		{"image source", func(m *v1beta1.SBOMSyft) { m.Spec.Syft.SyftSource.Type = "image" }, false},
		{"bad source", func(m *v1beta1.SBOMSyft) { m.Spec.Syft.SyftSource.Metadata = json.RawMessage(`{}`) }, false},
		{"unknown schema", func(m *v1beta1.SBOMSyft) { m.Spec.Syft.Schema.Version = "999.0.0" }, false},
		{"no distro", func(m *v1beta1.SBOMSyft) { m.Spec.Syft.Distro = v1beta1.LinuxRelease{} }, false},
		{"incomplete", func(m *v1beta1.SBOMSyft) { m.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Incomplete }, false},
		{"too large", func(m *v1beta1.SBOMSyft) { m.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge }, false},
		{"no provenance", func(m *v1beta1.SBOMSyft) { m.UID = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := readyHostInventory()
			tc.change(fixture)
			_, err := NewFakeAPIServerStorage("kubescape", fixture).GetHostSBOM(context.Background(), "node.a")
			require.Error(t, err)
			require.Equal(t, tc.pending, errors.Is(err, domain.ErrHostInventoryPending))
			if !tc.pending {
				require.ErrorIs(t, err, domain.ErrHostInventoryUnavailable)
			}
		})
	}
	repo := NewFakeAPIServerStorage("kubescape", readyHostInventory())
	_, err := repo.GetHostSBOM(context.Background(), "node-a")
	require.ErrorIs(t, err, domain.ErrHostInventoryPending, "must not fall back to sanitization-colliding node.a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = repo.GetHostSBOM(ctx, "node.a")
	require.ErrorIs(t, err, context.Canceled)
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	_, err = repo.GetHostSBOM(expired, "node.a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, domain.ErrHostInventoryPending)
}

func TestGetHostSBOMAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		pending bool
	}{
		{"timeout", apierrors.NewTimeoutError("timed out", 1), true},
		{"unavailable", apierrors.NewServiceUnavailable("down"), true},
		{"throttled", apierrors.NewTooManyRequests("busy", 1), true},
		{"forbidden", apierrors.NewForbidden(schema.GroupResource{Resource: "sbomsyfts"}, "host", errors.New("denied")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeStorageClientset()
			client.PrependReactor("get", "sbomsyfts", func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, tc.err })
			_, err := newFakeAPIServerStore("kubescape", client.SpdxV1beta1()).GetHostSBOM(context.Background(), "node.a")
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.pending, errors.Is(err, domain.ErrHostInventoryPending))
			require.Len(t, client.Actions(), 1)
			require.Equal(t, "get", client.Actions()[0].GetVerb())
		})
	}
}
