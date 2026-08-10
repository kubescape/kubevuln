package v1

import (
	"context"
	"errors"
	"testing"

	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockPBScannerClient struct {
	createSBOMErr error
}

func (m *mockPBScannerClient) CreateSBOM(_ context.Context, _ *pb.CreateSBOMRequest, _ ...grpc.CallOption) (*pb.CreateSBOMResponse, error) {
	return nil, m.createSBOMErr
}

func (m *mockPBScannerClient) Health(_ context.Context, _ *pb.HealthRequest, _ ...grpc.CallOption) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Ready: true}, nil
}

func TestCreateSBOM_WrapsGRPCDeadlineExceeded(t *testing.T) {
	c := &sbomScannerClient{client: &mockPBScannerClient{createSBOMErr: status.Error(codes.DeadlineExceeded, "context deadline exceeded")}}

	_, err := c.CreateSBOM(context.Background(), ScanRequest{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
	assert.NotErrorIs(t, err, ErrScannerUnavailable)
}

func TestCreateSBOM_PassesThroughPlainDeadlineExceeded(t *testing.T) {
	c := &sbomScannerClient{client: &mockPBScannerClient{createSBOMErr: context.DeadlineExceeded}}

	_, err := c.CreateSBOM(context.Background(), ScanRequest{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
	assert.NotErrorIs(t, err, ErrScannerUnavailable)
}

func TestCreateSBOM_WrapsGRPCTransportCodes(t *testing.T) {
	c := &sbomScannerClient{client: &mockPBScannerClient{
		createSBOMErr: status.Error(codes.Unavailable, "transport interrupted"),
	}}

	_, err := c.CreateSBOM(context.Background(), ScanRequest{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrScannerUnavailable)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
}

func TestCreateSBOM_DoesNotWrapGRPCAbortedAsUnavailable(t *testing.T) {
	c := &sbomScannerClient{client: &mockPBScannerClient{
		createSBOMErr: status.Error(codes.Aborted, "request aborted"),
	}}

	_, err := c.CreateSBOM(context.Background(), ScanRequest{})
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrScannerUnavailable)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
}

func TestCreateSBOM_PassesThroughUnrelatedError(t *testing.T) {
	unrelated := errors.New("some other error")
	c := &sbomScannerClient{client: &mockPBScannerClient{
		createSBOMErr: unrelated,
	}}

	_, err := c.CreateSBOM(context.Background(), ScanRequest{})
	assert.ErrorIs(t, err, unrelated)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
	assert.NotErrorIs(t, err, ErrScannerUnavailable)
}
