package repositories

import (
	"context"
	"errors"

	"github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
)

// errNoClusterConnection is returned by the label resolvers so that a
// selector-based exception fails closed when no cluster is available.
var errNoClusterConnection = errors.New("security exception label resolution requires a cluster connection")

// NoOpSecurityExceptionRepository returns empty results for environments
// where SecurityException CRDs are not available (e.g., local/test mode).
type NoOpSecurityExceptionRepository struct{}

func (n *NoOpSecurityExceptionRepository) GetSecurityExceptions(_ context.Context, _ string) ([]v1beta1.SecurityException, []v1beta1.ClusterSecurityException, error) {
	return nil, nil, nil
}

func (n *NoOpSecurityExceptionRepository) GetWorkloadLabels(_ context.Context, _, _, _ string) (map[string]string, error) {
	return nil, errNoClusterConnection
}

func (n *NoOpSecurityExceptionRepository) GetNamespaceLabels(_ context.Context, _ string) (map[string]string, error) {
	return nil, errNoClusterConnection
}
