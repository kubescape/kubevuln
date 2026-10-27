// Package sbomreuse acquires signed build inventories for explicitly trusted repositories.
// A valid signature authenticates a producer; it does not prove inventory completeness.
package sbomreuse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
)

// Policy is a startup snapshot. Changing a mounted file requires restarting kubevuln.
// Repository names are exact, canonical OCI repository names, never wildcard patterns.
type Policy struct {
	Repositories   map[string]Producer `json:"repositories"`
	MaxBytes       int64               `json:"maxBytes"`
	MaxCandidates  int                 `json:"maxCandidates"`
	TimeoutSeconds int                 `json:"timeoutSeconds"`
}

type Producer struct {
	PublicKeys    []string `json:"publicKeys"`
	SyftVersion   string   `json:"syftVersion"`
	SchemaVersion string   `json:"schemaVersion"`
}

type trust struct {
	Producer
	keys map[string]ed25519.PublicKey
}

// CompiledPolicy owns a validated, immutable copy of the administrator's policy.
type CompiledPolicy struct {
	repositories  map[string]trust
	fingerprint   string
	maxBytes      int64
	maxCandidates int
	timeout       time.Duration
}

func LoadPolicy(path string) (*CompiledPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 256*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 256*1024 {
		return nil, fmt.Errorf("SBOM trust policy exceeds 256 KiB")
	}
	var p Policy
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("decoding SBOM trust policy: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after SBOM trust policy")
	}
	return CompilePolicy(p)
}

func CompilePolicy(p Policy) (*CompiledPolicy, error) {
	if p.MaxBytes == 0 {
		p.MaxBytes = 8 * 1024 * 1024
	}
	if p.MaxCandidates == 0 {
		p.MaxCandidates = 8
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 10
	}
	if p.MaxBytes < 1024 || p.MaxBytes > 64*1024*1024 || p.MaxCandidates < 1 || p.MaxCandidates > 32 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 60 {
		return nil, fmt.Errorf("SBOM policy limits outside supported ranges")
	}
	if len(p.Repositories) == 0 {
		return nil, fmt.Errorf("SBOM policy requires an approved repository")
	}
	c := &CompiledPolicy{repositories: map[string]trust{}, maxBytes: p.MaxBytes, maxCandidates: p.MaxCandidates, timeout: time.Duration(p.TimeoutSeconds) * time.Second}
	for repo, producer := range p.Repositories {
		r, err := reference.ParseNormalizedNamed(repo)
		if err != nil || !reference.IsNameOnly(r) {
			return nil, fmt.Errorf("SBOM policy repository must be canonical: %q", repo)
		}
		// Keep the registry client's canonical spelling (including index.docker.io),
		// while validating paths with the complete distribution repository grammar.
		registry, err := name.NewRegistry(reference.Domain(r), name.StrictValidation)
		if err != nil || registry.Repo(reference.Path(r)).Name() != repo {
			return nil, fmt.Errorf("SBOM policy repository must be canonical: %q", repo)
		}
		if producer.SyftVersion == "" || producer.SchemaVersion == "" || len(producer.PublicKeys) == 0 {
			return nil, fmt.Errorf("repository %q requires a producer version, schema and public key", repo)
		}
		t := trust{Producer: producer, keys: map[string]ed25519.PublicKey{}}
		for _, encoded := range producer.PublicKeys {
			block, rest := pem.Decode([]byte(encoded))
			if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("repository %q requires a PKIX public key", repo)
			}
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("repository %q has an invalid public key", repo)
			}
			pub, ok := key.(ed25519.PublicKey)
			if !ok || len(pub) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("repository %q requires Ed25519 public keys", repo)
			}
			h := sha256.Sum256(block.Bytes)
			t.keys[hex.EncodeToString(h[:])] = bytes.Clone(pub)
		}
		// Do not retain caller-owned slices in the compiled policy.
		t.PublicKeys = nil
		c.repositories[repo] = t
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	c.fingerprint = hex.EncodeToString(h[:])
	return c, nil
}
