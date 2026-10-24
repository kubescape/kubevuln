package sbomreuse

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func testPolicy(t *testing.T, repository string) (Policy, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return Policy{Repositories: map[string]Producer{repository: {PublicKeys: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}, SyftVersion: "1.32.0", SchemaVersion: "16.0.39"}}}, key
}

func TestPolicyScopeAndRotation(t *testing.T) {
	p, _ := testPolicy(t, "registry.example/team/image")
	c, err := CompilePolicy(p)
	require.NoError(t, err)
	_, approved := c.repositories["registry.example/team/image-other"]
	require.False(t, approved)
	first := c.fingerprint
	p2, _ := testPolicy(t, "registry.example/team/image")
	c2, err := CompilePolicy(p2)
	require.NoError(t, err)
	require.NotEqual(t, first, c2.fingerprint)
	delete(p.Repositories, "registry.example/team/image")
	require.Len(t, c.repositories, 1)
}

func TestPolicyRejectsInvalidConfiguration(t *testing.T) {
	for _, mutation := range []func(*Policy){
		func(p *Policy) { p.MaxBytes = -1 }, func(p *Policy) { p.MaxCandidates = 100 }, func(p *Policy) { p.TimeoutSeconds = 61 },
		func(p *Policy) { p.Repositories = nil },
		func(p *Policy) { p.Repositories["image"] = p.Repositories["registry.example/team/image"] },
		func(p *Policy) {
			v := p.Repositories["registry.example/team/image"]
			v.PublicKeys = []string{"not a key"}
			p.Repositories["registry.example/team/image"] = v
		},
	} {
		p, _ := testPolicy(t, "registry.example/team/image")
		mutation(&p)
		_, err := CompilePolicy(p)
		require.Error(t, err)
	}
}
