package v1

import (
	"context"
	"errors"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var (
	ErrScannerCrashed  = errors.New("SBOM scanner sidecar crashed during scan")
	ErrScannerNotReady = errors.New("SBOM scanner sidecar not ready")
)

// ScanRequest contains all parameters needed for a registry-based SBOM scan.
type ScanRequest struct {
	ImageID             string
	ImageTag            string
	Options             domain.RegistryOptions
	MaxImageSize        int64
	MaxSBOMSize         int32
	EnableEmbeddedSBOMs bool
	Timeout             time.Duration
}

// ScanResult contains the SBOM document and metadata from a successful scan.
type ScanResult struct {
	SyftDocument *v1beta1.SyftDocument
	SBOMSize     int64
	Status       string
	ErrorMessage string
}

// SBOMScannerClient is the interface for communicating with the sidecar scanner.
type SBOMScannerClient interface {
	CreateSBOM(ctx context.Context, req ScanRequest) (*ScanResult, error)
	Health(ctx context.Context) (version string, ready bool, err error)
	Ready() bool
	Close() error
}
