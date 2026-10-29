package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	adapter "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/sbomreuse"
	"github.com/stretchr/testify/require"
)

func TestPublishAndImport(t *testing.T) {
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer s.Close()
	repo, err := name.NewRepository(strings.TrimPrefix(s.URL, "http://")+"/example", name.Insecure)
	require.NoError(t, err)
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	h, err := img.Digest()
	require.NoError(t, err)
	ref := repo.Digest(h.String())
	require.NoError(t, remote.Write(ref, img))
	opts := domain.RegistryOptions{InsecureUseHTTP: true, Platform: "linux/amd64"}
	local := adapter.NewSyftAdapter(time.Minute, 1024*1024, 1024*1024, false, nil)
	b, err := local.CreateSBOM(context.Background(), "example", ref.Name(), "", opts)
	require.NoError(t, err)
	raw, err := json.Marshal(b.Content)
	require.NoError(t, err)
	var header struct {
		Descriptor struct {
			Version string `json:"version"`
		} `json:"descriptor"`
	}
	require.NoError(t, json.Unmarshal(raw, &header))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	sbomPath := filepath.Join(dir, "sbom.json")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600))
	require.NoError(t, os.WriteFile(sbomPath, raw, 0600))
	first, err := publish(context.Background(), ref.Name(), sbomPath, keyPath, true)
	require.NoError(t, err)
	second, err := publish(context.Background(), ref.Name(), sbomPath, keyPath, true)
	require.NoError(t, err)
	require.Equal(t, first, second)
	p, err := sbomreuse.CompilePolicy(sbomreuse.Policy{Repositories: map[string]sbomreuse.Producer{repo.Name(): {PublicKeys: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}, SyftVersion: header.Descriptor.Version, SchemaVersion: "16.0.39"}}})
	require.NoError(t, err)
	imported, err := sbomreuse.NewProvider(p).Acquire(context.Background(), "example", ref.Name(), opts)
	require.NoError(t, err)
	require.Equal(t, b.Content, imported.Content)
	_, err = publish(context.Background(), repo.Tag("latest").Name(), sbomPath, keyPath, true)
	require.ErrorContains(t, err, "immutable")
	t.Log("PUBLISH_IMPORT: real Syft inventory, idempotent DSSE/OCI publication, verified import, exact document parity")
}
