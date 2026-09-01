package registryauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ResolveSource is generic over what a pull returns, so the ladder can be exercised without
// Syft. The sidecar and the in-process adapter both reach it with their own source type.
type fakeSource struct{ ref string }

func TestResolveSource_RetriesTagOnManifestUnknown(t *testing.T) {
	var tried []string
	get := func(_ context.Context, ref string, _ *image.RegistryOptions) (fakeSource, error) {
		tried = append(tried, ref)
		if ref == "repo@sha256:deadbeef" {
			return fakeSource{}, errors.New("MANIFEST_UNKNOWN: manifest unknown")
		}
		return fakeSource{ref: ref}, nil
	}

	src, err := ResolveSource(context.Background(), "in_process", get,
		"repo@sha256:deadbeef", "repo:latest", image.RegistryOptions{})

	require.NoError(t, err)
	assert.Equal(t, "repo:latest", src.ref)
	assert.Equal(t, []string{"repo@sha256:deadbeef", "repo:latest"}, tried)
}

// A registry that refuses our credentials may still serve the image anonymously, so a 401
// falls back to a pull with none. No provider matches a plain docker.io reference, so this
// goes straight to the anonymous attempt.
func TestResolveSource_FallsBackToAnonymousOn401(t *testing.T) {
	var credentialsSeen []int
	get := func(_ context.Context, ref string, opts *image.RegistryOptions) (fakeSource, error) {
		credentialsSeen = append(credentialsSeen, len(opts.Credentials))
		if len(opts.Credentials) > 0 {
			return fakeSource{}, errors.New("401 Unauthorized")
		}
		return fakeSource{ref: ref}, nil
	}

	opts := image.RegistryOptions{Credentials: []image.RegistryCredentials{{Username: "u", Password: "p"}}}
	src, err := ResolveSource(context.Background(), "in_process", get, "docker.io/library/nginx:1.25", "docker.io/library/nginx:1.25", opts)

	require.NoError(t, err)
	assert.Equal(t, "docker.io/library/nginx:1.25", src.ref)
	assert.Equal(t, []int{1, 0}, credentialsSeen, "the retry must drop the credentials that were refused")
}

// The caller's options must not be modified: the ladder swaps credentials as it retries, and
// a caller reusing its RegistryOptions for a later pull would otherwise inherit that.
func TestResolveSource_DoesNotMutateCallerOptions(t *testing.T) {
	get := func(_ context.Context, _ string, _ *image.RegistryOptions) (fakeSource, error) {
		return fakeSource{}, errors.New("401 Unauthorized")
	}

	opts := image.RegistryOptions{Credentials: []image.RegistryCredentials{{Username: "u", Password: "p"}}}
	_, err := ResolveSource(context.Background(), "in_process", get, "docker.io/library/nginx:1.25", "docker.io/library/nginx:1.25", opts)

	require.Error(t, err)
	require.Len(t, opts.Credentials, 1, "the caller's credentials must survive the anonymous retry")
	assert.Equal(t, "u", opts.Credentials[0].Username)
}

// An error that is neither MANIFEST_UNKNOWN nor a 401 is returned as it is, with one attempt.
func TestResolveSource_PassesOtherErrorsStraightBack(t *testing.T) {
	attempts := 0
	boom := errors.New("no route to host")
	get := func(_ context.Context, _ string, _ *image.RegistryOptions) (fakeSource, error) {
		attempts++
		return fakeSource{}, boom
	}

	_, err := ResolveSource(context.Background(), "in_process", get, "repo:tag", "repo:tag", image.RegistryOptions{})

	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, attempts)
}

// TestResolveSource_DoesNotFallBackToAnonymousOnNonAuthErrorFromCredentialedRetry is a
// regression test for #921: a credentialed retry that fails for a reason other than 401 (here,
// a 429) must not trigger a further, doomed-to-fail anonymous retry. The registry was never
// rejecting the request for being unauthenticated, so dropping credentials cannot fix it, and
// the real error must be returned as-is rather than masked as an authorization failure.
func TestResolveSource_DoesNotFallBackToAnonymousOnNonAuthErrorFromCredentialedRetry(t *testing.T) {
	origGCPCredsFn := GCPCredsFn
	defer func() { GCPCredsFn = origGCPCredsFn; ResetCaches() }()
	GCPCredsFn = func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: "tok"}, time.Now().Add(time.Hour), nil
	}

	rateLimited := errors.New("429 Too Many Requests")
	var credentialsSeen []int
	get := func(_ context.Context, _ string, opts *image.RegistryOptions) (fakeSource, error) {
		credentialsSeen = append(credentialsSeen, len(opts.Credentials))
		if len(opts.Credentials) == 0 {
			return fakeSource{}, errors.New("401 Unauthorized")
		}
		return fakeSource{}, rateLimited
	}

	_, err := ResolveSource(context.Background(), "in_process", get,
		"gcr.io/project/image:tag", "gcr.io/project/image:tag", image.RegistryOptions{})

	require.ErrorIs(t, err, rateLimited, "the credentialed retry's real error must come back, not be masked as unauthorized")
	assert.Equal(t, []int{0, 1}, credentialsSeen, "no third, anonymous attempt should follow a non-401 error from the credentialed retry")
}

// TestResolveSource_FallsBackToAnonymousWhenCredentialedRetryAlsoGets401 guards the behavior
// the #921 fix must preserve: credentials that are outright refused (401 again, not some other
// error) still fall back to anonymous access, exactly as ResolveSource's own doc comment
// describes.
func TestResolveSource_FallsBackToAnonymousWhenCredentialedRetryAlsoGets401(t *testing.T) {
	origGCPCredsFn := GCPCredsFn
	defer func() { GCPCredsFn = origGCPCredsFn; ResetCaches() }()
	GCPCredsFn = func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: "refused-token"}, time.Now().Add(time.Hour), nil
	}

	// Both the initial no-credentials attempt and the eventual anonymous retry pass zero
	// credentials, so the fixture distinguishes them by call order rather than credential
	// count: the first two attempts (no credentials, then the refused credentials) both fail
	// with 401, and only the third (anonymous, after the credentialed retry is also refused)
	// succeeds.
	var credentialsSeen []int
	get := func(_ context.Context, ref string, opts *image.RegistryOptions) (fakeSource, error) {
		credentialsSeen = append(credentialsSeen, len(opts.Credentials))
		if len(credentialsSeen) < 3 {
			return fakeSource{}, errors.New("401 Unauthorized")
		}
		return fakeSource{ref: ref}, nil
	}

	src, err := ResolveSource(context.Background(), "in_process", get,
		"gcr.io/project/image:tag", "gcr.io/project/image:tag", image.RegistryOptions{})

	require.NoError(t, err)
	assert.Equal(t, "gcr.io/project/image:tag", src.ref)
	assert.Equal(t, []int{0, 1, 0}, credentialsSeen, "a credentialed retry refused again must still fall back to anonymous")
}
