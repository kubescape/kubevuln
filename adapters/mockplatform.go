package adapters

import (
	"context"

	"github.com/armosec/armoapi-go/scanfailure"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

// MockPlatform implements a mocked Platform to be used for tests
type MockPlatform struct {
	wantEmptyReport       bool
	securityExceptionRepo ports.SecurityExceptionRepository
}

var _ ports.Platform = (*MockPlatform)(nil)

// NewMockPlatform initializes the MockPlatform struct
func NewMockPlatform(wantEmptyReport bool, seRepo ports.SecurityExceptionRepository) *MockPlatform {
	logger.L().Info("keepLocal config is true, statuses and scan reports won't be sent to Armo cloud")
	return &MockPlatform{
		wantEmptyReport:       wantEmptyReport,
		securityExceptionRepo: seRepo,
	}
}

// GetCVEExceptions returns CRD-based SecurityException policies
func (m MockPlatform) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error) {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.GetCVEExceptions")
	defer span.End()

	if m.securityExceptionRepo == nil {
		return domain.CVEExceptions{}, nil
	}

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.CVEExceptions{}, nil
	}

	namespace := wlidpkg.GetNamespaceFromWlid(workload.Wlid)
	seList, cseList, err := m.securityExceptionRepo.GetSecurityExceptions(ctx, namespace)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to get CRD security exceptions", helpers.Error(err))
		return domain.CVEExceptions{}, nil
	}

	if len(seList) > 0 || len(cseList) > 0 {
		policies := v1.ConvertToVulnerabilityExceptionPolicies(seList, cseList)
		return policies, nil
	}

	return domain.CVEExceptions{}, nil
}

func (m MockPlatform) ReportError(ctx context.Context, _ error) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.ReportError")
	defer span.End()
	return nil
}

func (m MockPlatform) ReportScanFailure(ctx context.Context, _ scanfailure.ScanFailureCase, _ string, _ error) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.ReportScanFailure")
	defer span.End()
	return nil
}

// SendStatus logs the given status and details
func (m MockPlatform) SendStatus(ctx context.Context, _ int) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.SendStatus")
	defer span.End()
	return nil
}

// SubmitCVE logs the given ID for CVE calculation
func (m MockPlatform) SubmitCVE(ctx context.Context, _ domain.CVEManifest, _ domain.CVEManifest) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.SubmitCVE")
	defer span.End()
	return nil
}

