package registryauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/internal/metrics"
)

// Getter pulls an image source for a reference. It is generic over the source type so this
// package stays free of Syft: the fallback ladder below cares about which reference and
// which credentials to try, not about what comes back.
type Getter[T any] func(ctx context.Context, ref string, opts *image.RegistryOptions) (T, error)

// isAuthDenied reports whether err is a registry rejecting the request as unauthenticated or
// unauthorized -- the two outcomes credentials (ours, or none at all) can actually change.
// Matches the same bucket core/services/scan_failure_reasons.go's classifySBOMError already
// uses for the identical distinction (401 vs. 403 both mean "the registry looked at who's
// asking and said no", where a 429/5xx/timeout means something else went wrong that swapping
// credentials cannot fix).
func isAuthDenied(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "401 Unauthorized") || strings.Contains(err.Error(), "403 Forbidden"))
}

// ResolveSource pulls imageID, falling back in order when the pull fails:
//
//   - MANIFEST_UNKNOWN, which a registry returns for a digest it does not hold, is retried
//     against imageTag.
//   - 401 Unauthorized is retried with credentials from the provider matching the reference
//     (ECR, GCP), and then, if that provider has none or its credentials are refused too,
//     without credentials at all. A registry that rejects our credentials may still serve
//     the image anonymously.
//
// component is the metrics label for the caller (in_process or sidecar), and ctx is used for
// the credential lookup and the metrics, not for the pull: both callers hand the pull a
// context of their own choosing.
//
// Both SBOM paths need this ladder and had a copy each. One copy is worth keeping here:
// those two drifting apart is where #585, #587, #601 and #675 came from, and the sidecar's
// copy had already reimplemented For inline rather than calling it.
func ResolveSource[T any](ctx context.Context, component string, get Getter[T], imageID, imageTag string, opts image.RegistryOptions) (T, error) {
	pullRef := imageID
	usedFallback := false

	src, err := get(ctx, pullRef, &opts)

	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		usedFallback = true
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		pullRef = imageTag
		src, err = get(ctx, pullRef, &opts)
	}

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		usedFallback = true
		unauthorizedErr := err
		if provider, ok := For(pullRef); ok {
			if creds, credErr := provider.Credentials(ctx, pullRef); credErr != nil || creds == nil {
				metrics.RecordScanFallback(ctx, component, metrics.FallbackCategoryRegistryAuth, provider.Strategy(), metrics.FallbackOutcomeFailed)
				logger.L().Debug("registry auth provider credentials unavailable, falling back to anonymous",
					helpers.Error(credErr),
					helpers.String("imageID", imageID))
			} else {
				opts.Credentials = []image.RegistryCredentials{*creds}
				src, err = get(ctx, pullRef, &opts)
				outcome := metrics.FallbackOutcomeFailed
				if err == nil {
					outcome = metrics.FallbackOutcomeSucceeded
				}
				metrics.RecordScanFallback(ctx, component, metrics.FallbackCategoryRegistryAuth, provider.Strategy(), outcome)
			}
		}
		// If no provider matched, its credentials were unavailable, or it succeeded in auth
		// but still got denied, fall back to anonymous access. err/src retain the last attempt.
		//
		// The isAuthDenied check matters: when a provider's credentials were used above, err
		// may now hold whatever the credentialed retry actually failed with, not another
		// auth rejection -- a 429, a 5xx, a timeout. None of those are fixed by dropping
		// credentials and retrying anonymously (the registry was never rejecting the request
		// for being unauthenticated), so without this check a persistently-429ing registry
		// gets a second full attempt -- itself wrapped in its own retry-with-backoff by every
		// caller -- doubling load on a registry that just asked to be backed off from, and the
		// eventual error permanently mislabels whatever actually went wrong as "unauthorized"
		// (via unauthorizedErr below). When no provider matched or its credentials were
		// unavailable, err is untouched here and still holds the original auth-denied error
		// from line 50 (or the MANIFEST_UNKNOWN retry above it), so this check doesn't change
		// that path's existing behavior. See #921.
		if isAuthDenied(err) {
			logger.L().Debug("retrying without credentials",
				helpers.String("imageID", imageID))
			opts.Credentials = nil
			src, err = get(ctx, pullRef, &opts)
			outcome := metrics.FallbackOutcomeFailed
			if err == nil {
				outcome = metrics.FallbackOutcomeSucceeded
			}
			metrics.RecordScanFallback(ctx, component, metrics.FallbackCategoryRegistryAuth, metrics.FallbackStrategyAnonymous, outcome)
			if err != nil && !strings.Contains(err.Error(), "401 Unauthorized") {
				err = fmt.Errorf("%w (anonymous fallback failed: %v)", unauthorizedErr, err)
			}
		}
	}

	metrics.RecordSourceResolution(ctx, component, usedFallback, err == nil)
	return src, err
}
