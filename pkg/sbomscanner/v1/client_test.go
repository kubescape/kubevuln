package v1

import (
	"context"
	"errors"
	"testing"
	"time"

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

// The scanner protocol carries the scan timeout as whole seconds, and the server treats a
// non-positive TimeoutSeconds as unset and substitutes a five minute default. Truncating
// therefore inverts the setting at the low end: a sub-second timeout became zero and turned
// into a far longer deadline than the one configured. The in-process adapter passes the same
// scanTimeout straight to deadline.New, so the two paths read one config value differently.
func TestTimeoutSecondsForWire(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    int64
	}{
		{name: "the 5 minute default is exact", timeout: 5 * time.Minute, want: 300},
		{name: "whole seconds are exact", timeout: 90 * time.Second, want: 90},
		{name: "sub-second rounds up rather than reading as unset", timeout: 500 * time.Millisecond, want: 1},
		{name: "one nanosecond still counts as a timeout", timeout: time.Nanosecond, want: 1},
		{name: "fractional rounds up rather than shortening", timeout: 1500 * time.Millisecond, want: 2},
		{name: "just under a whole second rounds up", timeout: 2999 * time.Millisecond, want: 3},
		{name: "zero means use the server default", timeout: 0, want: 0},
		{name: "negative means use the server default", timeout: -1 * time.Second, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := timeoutSecondsForWire(tt.timeout)
			assert.Equal(t, tt.want, got)
			if tt.timeout > 0 {
				assert.NotZero(t, got, "a positive timeout must never reach the server as unset")
				assert.GreaterOrEqual(t, time.Duration(got)*time.Second, tt.timeout,
					"the wire value must not shorten the configured timeout")
			}
		})
	}
}
