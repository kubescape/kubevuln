package sbomreuse

import (
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func inventory(t *testing.T, s subject) []byte {
	t.Helper()
	d, err := remote.Get(s.ref)
	require.NoError(t, err)
	img, err := d.Image()
	require.NoError(t, err)
	cfg, err := img.RawConfigFile()
	require.NoError(t, err)
	b, err := json.Marshal(map[string]any{"schema": map[string]string{"version": "16.0.39"}, "descriptor": map[string]string{"name": "syft", "version": "1.32.0"}, "artifacts": []any{}, "source": map[string]any{"type": "image", "metadata": map[string]any{"manifestDigest": s.ref.DigestStr(), "imageID": s.configDigest, "manifest": d.Manifest, "config": cfg}}})
	require.NoError(t, err)
	return b
}

func TestCompatibilityAcceptsEmptyImageAndRejectsMismatches(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "")
	require.NoError(t, err)
	p, _ := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	producer := policy.repositories[repo.Name()]
	raw := inventory(t, s)
	doc, err := compatible(raw, s, producer)
	require.NoError(t, err)
	require.Empty(t, doc.Artifacts)
	type sourceMetadata struct {
		ManifestDigest string `json:"manifestDigest"`
		ImageID        string `json:"imageID"`
		Manifest       []byte `json:"manifest"`
		Config         []byte `json:"config"`
	}
	var source sourceMetadata
	require.Equal(t, "image", doc.SyftSource.Type)
	require.NoError(t, json.Unmarshal(doc.SyftSource.Metadata, &source))
	require.Equal(t, s.ref.DigestStr(), source.ManifestDigest)
	require.Equal(t, s.configDigest, source.ImageID)
	var original struct {
		Source struct {
			Metadata json.RawMessage `json:"metadata"`
		} `json:"source"`
	}
	require.NoError(t, json.Unmarshal(raw, &original))
	var expected sourceMetadata
	require.NoError(t, json.Unmarshal(original.Source.Metadata, &expected))
	require.Equal(t, expected, source)
	for _, mutation := range []func(map[string]any){
		func(d map[string]any) { delete(d, "artifacts") },
		func(d map[string]any) { d["artifacts"] = nil },
		func(d map[string]any) { d["schema"].(map[string]any)["version"] = "99.0" },
		func(d map[string]any) {
			d["source"].(map[string]any)["metadata"].(map[string]any)["imageID"] = "sha256:wrong"
		},
		func(d map[string]any) { d["source"].(map[string]any)["metadata"].(map[string]any)["config"] = "e30=" },
		func(d map[string]any) {
			d["source"].(map[string]any)["target"] = map[string]any{"manifestDigest": "sha256:wrong", "imageID": "sha256:wrong", "architecture": "arm64", "os": "linux"}
		},
		func(d map[string]any) { d["source"].(map[string]any)["target"] = nil },
	} {
		var d map[string]any
		require.NoError(t, json.Unmarshal(raw, &d))
		mutation(d)
		b, err := json.Marshal(d)
		require.NoError(t, err)
		_, err = compatible(b, s, producer)
		require.Error(t, err)
	}
}
