// Package registryauth resolves ambient cloud credentials for container registries that
// reject anonymous pulls.
//
// Both SBOM paths, the in-process Syft adapter and the sidecar scanner, retry a 401 with
// credentials before giving up and trying anonymous access. They used to carry their own
// copy of that logic, which is how the in-process path ended up supporting only GCP after
// the sidecar had been made extensible. The providers live here so a registry added for one
// path is available to the other.
//
// Each provider's Credentials call is cached (see cache.go) and keyed by registry host, so
// two different registries -- or two different AWS accounts that happen to share a region --
// never share a cache entry. Entries are reused until the cloud provider's own reported
// expiry (an ECR token, for example, is valid 12 hours), and
// concurrent scans racing a cache miss for the same key collapse into a single upstream
// fetch, so a burst of scans against the same registry doesn't turn into a burst of STS/ADC
// requests.
package registryauth

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/kubescape/kubevuln/internal/metrics"
	"golang.org/x/oauth2/google"
)

var (
	errNoAuthorizationData         = errors.New("ecr returned no authorization data")
	errMalformedAuthorizationToken = errors.New("ecr authorization token is not in user:password form")
)

// Provider supplies registry credentials for hosts it recognizes, so the retry logic can
// consult cloud-specific auth without hard-coding each one.
type Provider interface {
	// Matches reports whether this provider handles the given pull reference.
	Matches(imageID string) bool
	// Credentials fetches credentials for a pull reference this provider matches. The
	// reference is passed in because some registries encode the account or region needed
	// to request a token in the hostname itself.
	Credentials(ctx context.Context, imageID string) (*image.RegistryCredentials, error)
	// Strategy names this provider in fallback metrics, so a fallback is attributed to the
	// cloud it actually came from.
	Strategy() string
}

// Providers is the ordered list of fallbacks consulted on a 401 Unauthorized, before
// falling back to anonymous access.
var Providers = []Provider{GCP{}, ECR{}}

// For returns the first provider matching imageID, if any.
func For(imageID string) (Provider, bool) {
	for _, p := range Providers {
		if p.Matches(imageID) {
			return p, true
		}
	}
	return nil, false
}

func host(imageID string) string {
	h, _, _ := strings.Cut(imageID, "/")
	return h
}

// GCP resolves credentials for GCR and Artifact Registry hosts via Application Default
// Credentials, so a workload running with Workload Identity needs no pull secret.
type GCP struct{}

func (GCP) Matches(imageID string) bool { return IsGCPRegistry(imageID) }

func (GCP) Strategy() string { return metrics.FallbackStrategyGCPADC }

// gcpCache is keyed by registry host, not a single shared entry: although Application
// Default Credentials resolve from one ambient identity, workload identity federation can
// map different namespaces/projects to different service accounts, so nothing here
// guarantees the token is actually the same across every GCR/Artifact Registry host a pod
// happens to pull from. Keying by host keeps that assumption from ever being load-bearing.
var gcpCache = newCredentialCache(metrics.FallbackStrategyGCPADC)

func (GCP) Credentials(ctx context.Context, imageID string) (*image.RegistryCredentials, error) {
	return gcpCache.get(ctx, host(imageID), GCPCredsFn)
}

// IsGCPRegistry reports whether imageID is hosted on GCR or Artifact Registry.
func IsGCPRegistry(imageID string) bool {
	h := host(imageID)
	return h == "gcr.io" || strings.HasSuffix(h, ".gcr.io") || strings.HasSuffix(h, "-docker.pkg.dev")
}

func gcpCredentials(ctx context.Context) (*image.RegistryCredentials, time.Time, error) {
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, time.Time{}, err
	}
	return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: token.AccessToken}, token.Expiry, nil
}

// GCPCredsFn is an indirection over gcpCredentials so callers can be unit-tested without a
// live GCP environment.
var GCPCredsFn credentialFetch = gcpCredentials

// ecrHost matches an ECR registry hostname and captures its region. Covers the standard,
// FIPS and China partitions:
//
//	123456789012.dkr.ecr.us-east-1.amazonaws.com
//	123456789012.dkr.ecr-fips.us-east-1.amazonaws.com
//	123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn
//
// ECR Public (public.ecr.aws) is deliberately excluded: it serves anonymous pulls, so the
// existing anonymous fallback already handles it and requesting a token would be pointless.
var ecrHost = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`)

// ECR resolves credentials for Elastic Container Registry hosts via the ambient AWS
// credential chain, which on EKS means the pod's IAM role.
//
// This is the registry where a static pull secret hurts most: an ECR authorization token is
// valid for 12 hours, so a Secret holding one has to be rotated twice a day to keep working.
// Requesting a token per scan removes that entirely.
type ECR struct{}

func (ECR) Matches(imageID string) bool { return ecrRegion(imageID) != "" }

func (ECR) Strategy() string { return metrics.FallbackStrategyECR }

// ecrCache is keyed by registry host, not just region: an ECR hostname embeds both the
// account ID and the region (123456789012.dkr.ecr.us-east-1.amazonaws.com), and a token
// requested via the ambient credential chain is scoped to whichever account that chain
// resolves to for the request. Keying by region alone would let two different AWS accounts
// pulling from the same region collide on one cache entry -- the second account would be
// handed the first account's token and get a 401.
var ecrCache = newCredentialCache(metrics.FallbackStrategyECR)

func (ECR) Credentials(ctx context.Context, imageID string) (*image.RegistryCredentials, error) {
	region := ecrRegion(imageID)
	return ecrCache.get(ctx, host(imageID), func(ctx context.Context) (*image.RegistryCredentials, time.Time, error) {
		return ECRCredsFn(ctx, region)
	})
}

// ecrRegion returns the AWS region encoded in an ECR hostname, or "" if imageID is not an
// ECR reference. The region cannot be assumed from ambient config: a cluster in one region
// may well pull from a registry in another.
func ecrRegion(imageID string) string {
	m := ecrHost.FindStringSubmatch(host(imageID))
	if m == nil {
		return ""
	}
	return m[1]
}

func ecrCredentials(ctx context.Context, region string) (*image.RegistryCredentials, time.Time, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, time.Time{}, err
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, time.Time{}, err
	}
	return credentialsFromAuthorizationToken(out)
}

// credentialsFromAuthorizationToken decodes ECR's authorization token, which is base64 of
// "AWS:<password>". Split on the first colon only: the password is opaque and may contain
// colons of its own. The returned expiry comes straight from ECR (AuthorizationData's own
// ExpiresAt), not assumed from the package doc's "12 hours" -- that's ECR's stated default,
// not a contract, so the cache must not hard-code it.
func credentialsFromAuthorizationToken(out *ecr.GetAuthorizationTokenOutput) (*image.RegistryCredentials, time.Time, error) {
	if out == nil || len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return nil, time.Time{}, errNoAuthorizationData
	}
	var expiry time.Time
	if exp := out.AuthorizationData[0].ExpiresAt; exp != nil {
		expiry = *exp
	}
	raw, err := base64.StdEncoding.DecodeString(*out.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return nil, time.Time{}, err
	}
	username, password, found := strings.Cut(string(raw), ":")
	if !found {
		return nil, time.Time{}, errMalformedAuthorizationToken
	}
	return &image.RegistryCredentials{Username: username, Password: password}, expiry, nil
}

// ECRCredsFn is an indirection over ecrCredentials so callers can be unit-tested without a
// live AWS environment.
var ECRCredsFn = ecrCredentials

// ResetCaches clears both providers' cached credentials. Tests that override
// GCPCredsFn/ECRCredsFn need this so the next Credentials() call actually reaches the
// override instead of returning a value an earlier test already cached.
func ResetCaches() {
	gcpCache.reset()
	ecrCache.reset()
}
