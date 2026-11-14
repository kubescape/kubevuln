// sbom-publish publishes the experimental inventory profile from docs/sbom-reuse.md.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/kubescape/kubevuln/internal/sbomreuse"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type artifact []byte

func (a artifact) RawManifest() ([]byte, error)        { return a, nil }
func (a artifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

func main() {
	ref := flag.String("image", "", "immutable platform image repository@sha256:digest")
	sbom := flag.String("sbom", "", "Syft JSON inventory")
	key := flag.String("key", "", "PKCS8 Ed25519 private key PEM")
	insecure := flag.Bool("insecure", false, "use plain HTTP for a local registry")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	digest, err := publish(ctx, *ref, *sbom, *key, *insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(digest)
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds size limit")
	}
	return b, nil
}

func publish(ctx context.Context, imageRef, sbomPath, keyPath string, insecure bool) (string, error) {
	options := []name.Option{name.StrictValidation}
	if insecure {
		options = append(options, name.Insecure)
	}
	ref, err := name.NewDigest(imageRef, options...)
	if err != nil {
		return "", fmt.Errorf("image must be an immutable repository digest: %w", err)
	}
	raw, err := readBounded(sbomPath, 20*1024*1024)
	if err != nil {
		return "", err
	}
	var header struct {
		Source struct {
			Metadata struct {
				ManifestDigest string `json:"manifestDigest"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", err
	}
	if header.Source.Metadata.ManifestDigest != ref.DigestStr() {
		return "", fmt.Errorf("inventory does not describe the requested platform manifest")
	}
	keyBytes, err := readBounded(keyPath, 64*1024)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("expected a PKCS8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected an Ed25519 private key")
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	d, err := remote.Get(ref, opts...)
	if err != nil {
		return "", err
	}
	if !d.MediaType.IsImage() {
		return "", fmt.Errorf("publish against a platform manifest, not an index")
	}
	payload, err := json.Marshal(map[string]any{"_type": sbomreuse.StatementType, "subject": []any{map[string]any{"name": ref.Context().Name(), "digest": map[string]string{d.Digest.Algorithm: d.Digest.Hex}}}, "predicateType": sbomreuse.PredicateType, "predicate": json.RawMessage(raw)})
	if err != nil {
		return "", err
	}
	envelope, err := json.Marshal(dsse.Envelope{PayloadType: sbomreuse.ArtifactType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(private, dsse.PAE(sbomreuse.ArtifactType, payload)))}}})
	if err != nil {
		return "", err
	}
	layer := static.NewLayer(envelope, types.MediaType(sbomreuse.EnvelopeMediaType))
	if err := remote.WriteLayer(ref.Context(), layer, opts...); err != nil {
		return "", err
	}
	h, err := layer.Digest()
	if err != nil {
		return "", err
	}
	config := static.NewLayer([]byte("{}"), types.MediaType(sbomreuse.ArtifactType))
	if err := remote.WriteLayer(ref.Context(), config, opts...); err != nil {
		return "", err
	}
	ch, err := config.Digest()
	if err != nil {
		return "", err
	}
	m := struct {
		v1.Manifest
		ArtifactType string `json:"artifactType"`
	}{Manifest: v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Subject: &d.Descriptor, Config: v1.Descriptor{MediaType: types.MediaType(sbomreuse.ArtifactType), Digest: ch, Size: 2}, Layers: []v1.Descriptor{{MediaType: types.MediaType(sbomreuse.EnvelopeMediaType), Digest: h, Size: int64(len(envelope))}}}, ArtifactType: sbomreuse.ArtifactType}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	// Content addressing keeps publication idempotent; no existing tag is moved.
	h, _, err = v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	target := ref.Context().Digest(h.String())
	if err := remote.Put(target, artifact(b), opts...); err != nil {
		return "", err
	}
	return target.Name(), nil
}
