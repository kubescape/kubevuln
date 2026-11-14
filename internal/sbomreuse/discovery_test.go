package sbomreuse

import (
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

type rawArtifact []byte

func (r rawArtifact) RawManifest() ([]byte, error)        { return r, nil }
func (r rawArtifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

func publishEnvelope(t *testing.T, repo name.Repository, s subject, envelope []byte) {
	t.Helper()
	blob := static.NewLayer(envelope, types.MediaType(EnvelopeMediaType))
	require.NoError(t, remote.WriteLayer(repo, blob))
	h, err := blob.Digest()
	require.NoError(t, err)
	cfg := static.NewLayer([]byte("{}"), types.MediaType("application/vnd.in-toto+json"))
	require.NoError(t, remote.WriteLayer(repo, cfg))
	ch, err := cfg.Digest()
	require.NoError(t, err)
	m := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Subject: &s.descriptor, Config: v1.Descriptor{MediaType: types.MediaType("application/vnd.in-toto+json"), Digest: ch, Size: 2}, Layers: []v1.Descriptor{{MediaType: types.MediaType(EnvelopeMediaType), Digest: h, Size: int64(len(envelope))}}}
	b, err := json.Marshal(attestationManifest{Manifest: m, ArtifactType: ArtifactType})
	require.NoError(t, err)
	require.NoError(t, remote.Put(repo.Tag("attestation"), rawArtifact(b)))
}

func TestDiscoverAttachment(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "linux/amd64")
	require.NoError(t, err)
	p, _ := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	_, err = c.discover(s, policy)
	require.ErrorContains(t, err, "exactly one")
	publishEnvelope(t, repo, s, []byte(`{"payload":"example"}`))
	a, err := c.discover(s, policy)
	require.NoError(t, err)
	require.JSONEq(t, `{"payload":"example"}`, string(a.envelope))
	publishEnvelope(t, repo, s, []byte(`{"payload":"another"}`))
	_, err = c.discover(s, policy)
	require.ErrorContains(t, err, "exactly one")
}
