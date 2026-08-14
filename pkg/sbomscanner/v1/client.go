package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	healthCheckTimeout = 5 * time.Second
	MaxgRPCMessageSize = 128 * 1024 * 1024
	// DefaultReadinessTimeout is used when the caller does not configure an
	// explicit readiness timeout.
	DefaultReadinessTimeout = 60 * time.Second
	// readinessMaxInterval caps the exponential backoff between health checks so
	// the effective wait tracks readinessTimeout closely instead of overshooting
	// it by a full backoff interval.
	readinessMaxInterval = 5 * time.Second
)

type sbomScannerClient struct {
	conn   *grpc.ClientConn
	client pb.SBOMScannerClient
}

// NewSBOMScannerClient creates a gRPC client connected to the scanner sidecar via Unix socket.
// It performs a health check with exponential backoff before returning. The wait is bounded by
// readinessTimeout and cancelable via ctx, so it cannot block process startup indefinitely.
// If ctx is canceled before readiness is reached, the returned error satisfies
// errors.Is(err, context.Cause(ctx)) so callers can distinguish cancellation from a genuinely
// unhealthy sidecar.
// A readinessTimeout of zero or less does not mean "wait indefinitely": it makes the
// readiness deadline expire immediately, so the sidecar is treated as unready right away.
func NewSBOMScannerClient(ctx context.Context, socketPath string, readinessTimeout time.Duration) (SBOMScannerClient, error) {
	target := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxgRPCMessageSize),
			grpc.MaxCallSendMsgSize(MaxgRPCMessageSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	c := &sbomScannerClient{
		conn:   conn,
		client: pb.NewSBOMScannerClient(conn),
	}

	// Wait for the sidecar to become ready, bounded by readinessTimeout and
	// cancelable via ctx so an unhealthy sidecar cannot hang startup.
	readinessCtx, readinessCancel := context.WithTimeout(ctx, readinessTimeout)
	defer readinessCancel()
	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = readinessMaxInterval
	_, err = backoff.Retry(readinessCtx, func() (struct{}, error) {
		healthCtx, cancel := context.WithTimeout(readinessCtx, healthCheckTimeout)
		defer cancel()
		resp, err := c.client.Health(healthCtx, &pb.HealthRequest{})
		if err != nil {
			return struct{}{}, fmt.Errorf("health check failed: %w", err)
		}
		if !resp.Ready {
			return struct{}{}, fmt.Errorf("scanner not ready")
		}
		return struct{}{}, nil
	}, backoff.WithBackOff(bo), backoff.WithMaxElapsedTime(readinessTimeout))
	if err != nil {
		logger.L().Error("SBOM scanner sidecar health check failed after retries", helpers.Error(err))
		if err := conn.Close(); err != nil {
			logger.L().Debug("failed to close scanner connection", helpers.Error(err))
		}
		return nil, err
	}

	logger.L().Info("SBOM scanner sidecar connected")
	return c, nil
}

// timeoutSecondsForWire converts a scan timeout to the whole seconds the scanner protocol
// carries, rounding up so a configured timeout is never shortened.
//
// Truncating instead inverts the setting at the low end: the server treats a non-positive
// TimeoutSeconds as unset and falls back to a five minute default, so a sub-second timeout
// truncated to zero produces a far longer deadline than the one configured, not a shorter
// one. The in-process adapter passes the same scanTimeout straight to deadline.New and
// honours it exactly, so the two SBOM paths would otherwise read one config value very
// differently.
//
// A non-positive timeout is passed through as zero, which is the value that legitimately
// means "use the server default".
func timeoutSecondsForWire(timeout time.Duration) int64 {
	if timeout <= 0 {
		return 0
	}
	seconds := timeout / time.Second
	if timeout%time.Second != 0 {
		seconds++
	}
	return int64(seconds)
}

func (c *sbomScannerClient) CreateSBOM(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	// Map domain credentials to proto
	creds := make([]*pb.RegistryCredentials, len(req.Options.Credentials))
	for i, v := range req.Options.Credentials {
		creds[i] = &pb.RegistryCredentials{
			Authority: v.Authority,
			Username:  v.Username,
			Password:  v.Password,
			Token:     v.Token,
		}
	}

	pbReq := &pb.CreateSBOMRequest{
		ImageId:               req.ImageID,
		ImageTag:              req.ImageTag,
		Platform:              req.Options.Platform,
		Credentials:           creds,
		InsecureSkipTlsVerify: req.Options.InsecureSkipTLSVerify,
		InsecureUseHttp:       req.Options.InsecureUseHTTP,
		MaxImageSize:          req.MaxImageSize,
		MaxSbomSize:           req.MaxSBOMSize,
		EnableEmbeddedSboms:   req.EnableEmbeddedSBOMs,
		TimeoutSeconds:        timeoutSecondsForWire(req.Timeout),
	}

	resp, err := c.client.CreateSBOM(ctx, pbReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unavailable {
			return nil, fmt.Errorf("%w: %v", ErrScannerUnavailable, err)
		}
		if ok && st.Code() == codes.DeadlineExceeded {
			return nil, fmt.Errorf("scan timeout: %w: %v", context.DeadlineExceeded, err)
		}
		return nil, err
	}

	result := &ScanResult{
		SBOMSize:         resp.SbomSize,
		Status:           resp.Status,
		ErrorMessage:     resp.ErrorMessage,
		StatusReason:     resp.StatusReason,
		ResolvedPlatform: resp.ResolvedPlatform,
	}

	// Deserialize SBOM document if present
	if len(resp.SbomDocument) > 0 {
		var doc v1beta1.SyftDocument
		if err := json.Unmarshal(resp.SbomDocument, &doc); err != nil {
			return nil, fmt.Errorf("failed to deserialize SBOM document: %w", err)
		}
		result.SyftDocument = &doc
	}

	return result, nil
}

func (c *sbomScannerClient) Health(ctx context.Context) (string, bool, error) {
	resp, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return "", false, err
	}
	return resp.Version, resp.Ready, nil
}

func (c *sbomScannerClient) Ready() bool {
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()
	resp, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return false
	}
	return resp.Ready
}

func (c *sbomScannerClient) Close() error {
	return c.conn.Close()
}
