package sbomreuse

import (
	"context"
	"fmt"
	"net/http"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type subject struct {
	ref          name.Digest
	descriptor   v1.Descriptor
	platform     v1.Platform
	configDigest string
}

type registryClient struct {
	opts   []remote.Option
	budget *boundedTransport
}

func newRegistryClient(ctx context.Context, repository name.Repository, opts image.RegistryOptions, policy *CompiledPolicy) (*registryClient, error) {
	tls, err := opts.TLSConfig(repository.RegistryStr())
	if err != nil {
		return nil, err
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tls
	budget := &boundedTransport{base: base, maxBody: policy.maxBytes, remaining: 2*policy.maxBytes + 8*1024*1024}
	options := []remote.Option{remote.WithContext(ctx), remote.WithTransport(budget)}
	if a := opts.Authenticator(repository.RegistryStr()); a != nil {
		options = append(options, remote.WithAuth(a))
	} else if opts.Keychain != nil {
		options = append(options, remote.WithAuthFromKeychain(opts.Keychain))
	} else {
		options = append(options, remote.WithAuth(authn.Anonymous))
	}
	return &registryClient{opts: options, budget: budget}, nil
}

// resolve reads manifests and the image configuration, never image layers. An index
// requires an explicit platform and a unique matching child; ambiguous indexes fall back.
func (c *registryClient) resolve(ref name.Digest, platform string) (subject, error) {
	d, err := remote.Get(ref, c.opts...)
	if err != nil {
		return subject{}, err
	}
	var requested *v1.Platform
	if platform != "" {
		requested, err = v1.ParsePlatform(platform)
		if err != nil || requested.OS == "" || requested.Architecture == "" {
			return subject{}, fmt.Errorf("invalid image platform")
		}
	}
	if d.MediaType.IsIndex() {
		if requested == nil {
			return subject{}, fmt.Errorf("an image index requires an explicit platform")
		}
		idx, err := d.ImageIndex()
		if err != nil {
			return subject{}, err
		}
		manifest, err := idx.IndexManifest()
		if err != nil {
			return subject{}, err
		}
		if len(manifest.Manifests) > 128 {
			return subject{}, fmt.Errorf("image index exceeds candidate limit")
		}
		var candidates []v1.Descriptor
		for _, child := range manifest.Manifests {
			if child.Platform != nil && samePlatform(*child.Platform, *requested) {
				candidates = append(candidates, child)
			}
		}
		if len(candidates) != 1 {
			return subject{}, fmt.Errorf("image platform is missing or ambiguous")
		}
		ref = ref.Context().Digest(candidates[0].Digest.String())
		d, err = remote.Get(ref, c.opts...)
		if err != nil {
			return subject{}, err
		}
	}
	if !d.MediaType.IsImage() {
		return subject{}, fmt.Errorf("expected a platform image manifest")
	}
	img, err := d.Image()
	if err != nil {
		return subject{}, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return subject{}, err
	}
	actual := v1.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
	if actual.OS == "" || actual.Architecture == "" || (requested != nil && !samePlatform(actual, *requested)) {
		return subject{}, fmt.Errorf("image configuration does not match platform")
	}
	manifest, err := img.Manifest()
	if err != nil {
		return subject{}, err
	}
	if d.Digest.String() != ref.DigestStr() {
		return subject{}, fmt.Errorf("resolved image digest mismatch")
	}
	return subject{ref: ref, descriptor: d.Descriptor, platform: actual, configDigest: manifest.Config.Digest.String()}, nil
}

func samePlatform(a, b v1.Platform) bool {
	return a.OS == b.OS && a.Architecture == b.Architecture && a.Variant == b.Variant
}
