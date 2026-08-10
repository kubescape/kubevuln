package domain

import (
	"errors"

	"github.com/armosec/armoapi-go/identifiers"
	"github.com/docker/docker/api/types/registry"
)

const (
	ArgsName               = "name"
	ArgsNamespace          = "namespace"
	// ArgsPlatform lets a caller request a specific image platform (OCI "os/arch[/variant]",
	// or a bare arch such as "arm64") for SBOM generation, e.g. an operator populating it from
	// the scanned Pod's node architecture. Read via optionsFromWorkload into
	// RegistryOptions.Platform. Left unset, both SBOM adapters resolve whatever platform the
	// image manifest provides instead of forcing one (see #512).
	ArgsPlatform           = "platform"
	AttributeUseHTTP       = identifiers.AttributeUseHTTP
	AttributeSkipTLSVerify = identifiers.AttributeSkipTLSVerify
)

var (
	ErrExpectedError            = errors.New("expected error")
	ErrInitVulnDB               = errors.New("vulnerability DB is not initialized, run readiness probe")
	ErrIncompleteSBOM           = errors.New("incomplete SBOM, skipping CVE scan")
	ErrOutdatedSBOM             = errors.New("SBOM is outdated")
	ErrSBOMWithPartialArtifacts = errors.New("SBOM having partial artifacts")
	ErrInvalidScanID            = errors.New("invalid scanID")
	ErrPartialContainerProfile  = errors.New("container profile is partial (workload restart required)")
	ErrMissingCpInfo            = errors.New("missing container profile information")
	ErrMissingImageInfo         = errors.New("missing image information")
	ErrMissingSBOM              = errors.New("missing SBOM")
	ErrMissingScanID            = errors.New("missing scanID")
	ErrMissingTimestamp         = errors.New("missing timestamp")
	ErrCastingWorkload          = errors.New("casting workload")
	ErrMockError                = errors.New("mock error")
	ErrTooManyRequests          = errors.New("too many requests")
	// ErrExceptionsDegraded indicates the SecurityException set is incomplete
	// (e.g. the CRD list failed). Callers must not treat missing exceptions as
	// deletions.
	ErrExceptionsDegraded = errors.New("exception set is incomplete")
)

// ScanError wraps a scan-flow error together with the scanfailure.Reason* classification
// (github.com/armosec/armoapi-go/scanfailure) already computed at the point of failure, so
// callers up the stack — namely the HTTP controller's Prometheus metrics — can recover the
// specific reason via errors.As without re-deriving it from the error string. Unwrap exposes
// the original error unchanged, so existing errors.Is-based checks (e.g. against
// ErrTooManyRequests or ErrPartialContainerProfile) keep working exactly as before.
type ScanError struct {
	Reason string
	Err    error
}

func (e *ScanError) Error() string { return e.Err.Error() }
func (e *ScanError) Unwrap() error { return e.Err }

type ScanIDKey struct{}
type TimestampKey struct{}
type WorkloadKey struct{}

type ScanCommand struct {
	Args               map[string]interface{}
	ImageTagNormalized string
	ImageSlug          string
	InstanceID         string
	Wlid               string
	// deprecated
	ImageTag        string
	JobID           string
	ContainerName   string
	ParentJobID     string
	ImageHash       string
	CredentialsList []registry.AuthConfig
	Session         Session
	LastAction      int
}

type Session struct {
	JobIDs []string
}
