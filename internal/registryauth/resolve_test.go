package registryauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ResolveSource is generic over what a pull returns, so the ladder can be exercised without
// Syft. The sidecar and the in-process adapter both reach it with their own source type.
type fakeSource struct{ ref string }

func registryAuthError(t *testing.T, status int, code transport.ErrorCode) *transport.Error {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://europe-west1-docker.pkg.dev/v2/token?scope=repository:project/repo/image:pull", nil)
	require.NoError(t, err)
	return &transport.Error{
		StatusCode: status,
		Request:    req,
		Errors:     []transport.Diagnostic{{Code: code, Message: "Unauthenticated request."}},
	}
}

func flattenedRegistryAuthError(t *testing.T, code transport.ErrorCode) error {
	t.Helper()
	// Match stereoscope's formatting: the transport error's type is lost here.
	err := fmt.Errorf("oci-registry: failed to get image descriptor from registry: %+v",
		registryAuthError(t, http.StatusForbidden, code))
	var terr *transport.Error
	require.False(t, errors.As(err, &terr))
	require.NotContains(t, err.Error(), "401 Unauthorized")
	require.NotContains(t, err.Error(), "403 Forbidden")
	return err
}

func TestIsAuthDenied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed 401", registryAuthError(t, http.StatusUnauthorized, transport.DeniedErrorCode), true},
		{"wrapped typed 401", fmt.Errorf("pull failed: %w", registryAuthError(t, http.StatusUnauthorized, transport.DeniedErrorCode)), true},
		{"typed 403", registryAuthError(t, http.StatusForbidden, transport.DeniedErrorCode), true},
		{"wrapped typed 403", fmt.Errorf("pull failed: %w", registryAuthError(t, http.StatusForbidden, transport.UnauthorizedErrorCode)), true},
		{"flattened DENIED", flattenedRegistryAuthError(t, transport.DeniedErrorCode), true},
		{"flattened UNAUTHORIZED", flattenedRegistryAuthError(t, transport.UnauthorizedErrorCode), true},
		{"bare DENIED", errors.New("DENIED: Unauthenticated request."), true},
		{"bare UNAUTHORIZED", errors.New("UNAUTHORIZED: authentication required"), true},
		{"multiple diagnostics", errors.New("multiple errors returned: UNKNOWN: other error; DENIED: Unauthenticated request."), true},
		{"legacy 401", errors.New("pull failed: 401 Unauthorized"), true},
		{"legacy 403", errors.New("pull failed: 403 Forbidden"), true},
		{"typed 404 overrides diagnostic", registryAuthError(t, http.StatusNotFound, transport.DeniedErrorCode), false},
		{"typed 429 overrides diagnostic", registryAuthError(t, http.StatusTooManyRequests, transport.DeniedErrorCode), false},
		{"typed 500 overrides diagnostic", registryAuthError(t, http.StatusInternalServerError, transport.UnauthorizedErrorCode), false},
		{"wrapped 429 overrides text", fmt.Errorf("401 Unauthorized: %w", registryAuthError(t, http.StatusTooManyRequests, transport.DeniedErrorCode)), false},
		{"404", errors.New("404 Not Found"), false},
		{"429", errors.New("429 Too Many Requests"), false},
		{"500", errors.New("500 Internal Server Error"), false},
		{"timeout", context.DeadlineExceeded, false},
		{"filesystem permission", &os.PathError{Op: "open", Path: "/image", Err: os.ErrPermission}, false},
		{"embedded DENIED", errors.New("unexpected text DENIED: unrelated failure"), false},
		{"embedded UNAUTHORIZED", errors.New("unexpected text UNAUTHORIZED: unrelated failure"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAuthDenied(tt.err))
		})
	}
}

func TestResolveSource_StructuredAuthFallback(t *testing.T) {
	denied := flattenedRegistryAuthError(t, transport.DeniedErrorCode)
	unauthorized := flattenedRegistryAuthError(t, transport.UnauthorizedErrorCode)
	rateLimited := &transport.Error{StatusCode: http.StatusTooManyRequests}
	serverError := &transport.Error{StatusCode: http.StatusInternalServerError}
	const artifactRef = "europe-west1-docker.pkg.dev/project/repo/image:tag"
	tests := []struct {
		name      string
		imageID   string
		imageTag  string
		results   []error
		wantCreds []int
		wantRefs  []string
		wantErr   error
	}{
		{name: "Artifact Registry DENIED", imageID: artifactRef, results: []error{denied, nil}, wantCreds: []int{0, 1}},
		{name: "regional GCR DENIED", imageID: "eu.gcr.io/project/image:tag", results: []error{denied, nil}, wantCreds: []int{0, 1}},
		{name: "Artifact Registry UNAUTHORIZED", imageID: artifactRef, results: []error{unauthorized, nil}, wantCreds: []int{0, 1}},
		{name: "typed 403", imageID: artifactRef, results: []error{registryAuthError(t, http.StatusForbidden, transport.DeniedErrorCode), nil}, wantCreds: []int{0, 1}},
		{name: "credentials denied", imageID: artifactRef, results: []error{denied, denied, nil}, wantCreds: []int{0, 1, 0}},
		{name: "credentials unauthorized", imageID: artifactRef, results: []error{denied, unauthorized, nil}, wantCreds: []int{0, 1, 0}},
		{name: "credentialed 429", imageID: artifactRef, results: []error{denied, rateLimited}, wantCreds: []int{0, 1}, wantErr: rateLimited},
		{name: "credentialed 500", imageID: artifactRef, results: []error{denied, serverError}, wantCreds: []int{0, 1}, wantErr: serverError},
		{name: "credentialed timeout", imageID: artifactRef, results: []error{denied, context.DeadlineExceeded}, wantCreds: []int{0, 1}, wantErr: context.DeadlineExceeded},
		{
			name: "tag before authentication", imageID: "europe-west1-docker.pkg.dev/project/repo/image@sha256:deadbeef", imageTag: artifactRef,
			results: []error{errors.New("MANIFEST_UNKNOWN: manifest unknown"), denied, nil}, wantCreds: []int{0, 0, 1},
			wantRefs: []string{"europe-west1-docker.pkg.dev/project/repo/image@sha256:deadbeef", artifactRef, artifactRef},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := GCPCredsFn
			t.Cleanup(func() { GCPCredsFn = orig; ResetCaches() })
			ResetCaches()
			creds := image.RegistryCredentials{Username: "oauth2accesstoken", Password: "test-adc-token"}
			credentialCalls := 0
			GCPCredsFn = func(context.Context) (*image.RegistryCredentials, time.Time, error) {
				credentialCalls++
				return &creds, time.Now().Add(time.Hour), nil
			}
			var refs []string
			var credentialsSeen []int
			get := func(_ context.Context, ref string, opts *image.RegistryOptions) (fakeSource, error) {
				attempt := len(refs)
				require.Less(t, attempt, len(tt.results), "unexpected extra pull")
				refs = append(refs, ref)
				credentialsSeen = append(credentialsSeen, len(opts.Credentials))
				if len(opts.Credentials) > 0 {
					assert.Equal(t, []image.RegistryCredentials{creds}, opts.Credentials)
				}
				return fakeSource{ref: ref}, tt.results[attempt]
			}
			src, err := ResolveSource(context.Background(), "in_process", get, tt.imageID, tt.imageTag, image.RegistryOptions{})
			if tt.wantErr != nil {
				assert.True(t, err == tt.wantErr, "non-auth errors must be returned unchanged: got %v", err)
			} else {
				assert.NoError(t, err)
				wantRef := tt.imageID
				if tt.imageTag != "" {
					wantRef = tt.imageTag
				}
				assert.Equal(t, wantRef, src.ref)
			}
			assert.Equal(t, 1, credentialCalls)
			assert.Equal(t, tt.wantCreds, credentialsSeen)
			if tt.wantRefs != nil {
				assert.Equal(t, tt.wantRefs, refs)
			} else {
				for _, ref := range refs {
					assert.Equal(t, tt.imageID, ref)
				}
			}
		})
	}
}

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
