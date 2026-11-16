package sbomreuse

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

// inventoryWithPackage is inventory with one package whose licenses and CPEs are
// empty lists, as Syft writes them for many real packages.
func inventoryWithPackage(t *testing.T, s subject) []byte {
	t.Helper()
	d, err := remote.Get(s.ref)
	require.NoError(t, err)
	img, err := d.Image()
	require.NoError(t, err)
	cfg, err := img.RawConfigFile()
	require.NoError(t, err)
	pkg := map[string]any{
		"id": "4d9a3b1c2e5f6a7b", "name": "busybox", "version": "1.36.1-r0", "type": "apk",
		"foundBy":   "apk-db-cataloger",
		"locations": []any{map[string]any{"path": "/lib/apk/db/installed", "accessPath": "/lib/apk/db/installed"}},
		"licenses":  []any{}, "language": "", "cpes": []any{}, "purl": "pkg:apk/alpine/busybox@1.36.1-r0",
	}
	b, err := json.Marshal(map[string]any{
		"schema":                map[string]string{"version": "16.0.39"},
		"descriptor":            map[string]string{"name": "syft", "version": "1.32.0"},
		"artifacts":             []any{pkg},
		"artifactRelationships": []any{},
		"source": map[string]any{"type": "image", "metadata": map[string]any{
			"manifestDigest": s.ref.DigestStr(), "imageID": s.configDigest, "manifest": d.Manifest, "config": cfg,
		}},
	})
	require.NoError(t, err)
	return b
}

// storedAndReadBack is the document as the production storage client gets it back:
// it writes and reads SBOMs as application/vnd.kubernetes.protobuf, where an empty
// list and a missing one are the same.
func storedAndReadBack(t *testing.T, doc *v1beta1.SyftDocument) *v1beta1.SyftDocument {
	t.Helper()
	in := v1beta1.SBOMSyft{Spec: v1beta1.SBOMSyftSpec{Syft: *doc}}
	wire, err := in.Marshal()
	require.NoError(t, err)
	var out v1beta1.SBOMSyft
	require.NoError(t, out.Unmarshal(wire))
	return &out.Spec.Syft
}

// An imported inventory that storage has kept and returned is the same inventory, and
// a cache hit on it does not acquire it again.
func TestCachedImportIsEligibleAfterStorage(t *testing.T) {
	for name, payload := range map[string]func(*testing.T, subject) []byte{
		"a package with empty lists": inventoryWithPackage,
		"an image with no packages":  inventory,
	} {
		t.Run(name, func(t *testing.T) {
			repo, c := testRegistry(t)
			ref := publishImage(t, repo, "amd64")
			s, err := c.resolve(ref, "")
			require.NoError(t, err)
			p, key := testPolicy(t, repo.Name())
			policy, err := CompilePolicy(p)
			require.NoError(t, err)
			provider := NewProvider(policy)
			publishEnvelope(t, repo, s, signStatement(t, s, payload(t, s), key))
			opts := domain.RegistryOptions{InsecureUseHTTP: true}
			b, err := provider.Acquire(context.Background(), "image", ref.Name(), opts)
			require.NoError(t, err)
			require.True(t, provider.CachedEligible(b, ref.Name(), opts))

			b.Content = storedAndReadBack(t, b.Content)
			require.True(t, provider.CachedEligible(b, ref.Name(), opts), "the stored import is not eligible")
		})
	}
}
