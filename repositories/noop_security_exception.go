package repositories

import (
	"context"

	"github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
)

// NoOpSecurityExceptionRepository returns empty results for environments
// where SecurityException CRDs are not available (e.g., local/test mode).
type NoOpSecurityExceptionRepository struct{}

func (n *NoOpSecurityExceptionRepository) GetSecurityExceptions(_ context.Context, _ string) ([]v1beta1.SecurityException, []v1beta1.ClusterSecurityException, error) {
	return nil, nil, nil
}
