package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileRepository interface {
	GetContainerProfile(ctx context.Context, namespace string, name string) (v1beta1.ContainerProfile, error)
}

// CVERepository is the port implemented by adapters to be used in ScanService to store CVE manifests
type CVERepository interface {
	GetCVE(ctx context.Context, name, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (domain.CVEManifest, error)
	GetCVESummary(ctx context.Context) (*v1beta1.VulnerabilityManifestSummary, error)
	StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error
	StoreCVESummary(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error
	StoreCVESummaryStub(ctx context.Context, status string) error
	StoreVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error
}

// SBOMRepository is the port implemented by adapters to be used in ScanService to store SBOMs
type SBOMRepository interface {
	GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error)
	StoreSBOM(ctx context.Context, sbom domain.SBOM, isFiltered bool) error
}

// SecurityExceptionRepository reads SecurityException CRDs from the cluster and
// resolves the labels needed to evaluate objectSelector/namespaceSelector.
type SecurityExceptionRepository interface {
	GetSecurityExceptions(ctx context.Context, namespace string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error)
	// GetWorkloadLabels returns the labels of the given workload, used to
	// evaluate match.objectSelector. It returns an error when the workload cannot
	// be found or resolved, so the caller fails closed — a negative selector must
	// not match an unresolved workload's empty label set.
	GetWorkloadLabels(ctx context.Context, namespace, kind, name string) (map[string]string, error)
	// GetNamespaceLabels returns the labels of the given namespace, used to
	// evaluate match.namespaceSelector. It returns an error when the namespace
	// cannot be found or resolved (see GetWorkloadLabels).
	GetNamespaceLabels(ctx context.Context, name string) (map[string]string, error)
}
