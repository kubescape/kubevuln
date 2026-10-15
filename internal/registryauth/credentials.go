package registryauth

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/kubescape/kubevuln/core/domain"
)

// Credentials converts domain registry credentials into Stereoscope credentials.
//
// An identity token is an OAuth2 refresh token, not a bearer token, so it is passed to
// go-containerregistry as an authn.AuthConfig. The bearer transport then exchanges it at
// the registry's token endpoint (grant_type=refresh_token) and authenticates with the
// access token it gets back. It is only used when the entry has no basic pair and no
// registry token, so entries that already worked keep the same authenticator.
func Credentials(credentials []domain.RegistryCredentials) []image.RegistryCredentials {
	out := make([]image.RegistryCredentials, len(credentials))
	for i, c := range credentials {
		out[i] = image.RegistryCredentials{
			Authority: c.Authority,
			Username:  c.Username,
			Password:  c.Password,
			Token:     c.Token,
		}
		hasBasic := c.Username != "" && c.Password != ""
		if c.IdentityToken != "" && !hasBasic && c.Token == "" {
			out[i].Authenticator = authn.FromConfig(authn.AuthConfig{IdentityToken: c.IdentityToken})
		}
	}
	return out
}
