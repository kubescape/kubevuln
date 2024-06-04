package domain

import (
	"errors"

	"github.com/armosec/armoapi-go/identifiers"
	"github.com/docker/docker/api/types/registry"
)

const (
	ArgsName               = "name"
	ArgsNamespace          = "namespace"
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
	ErrMissingApInfo            = errors.New("missing application profile information")
	ErrMissingImageInfo         = errors.New("missing image information")
	ErrMissingSBOM              = errors.New("missing SBOM")
	ErrMissingScanID            = errors.New("missing scanID")
	ErrMissingTimestamp         = errors.New("missing timestamp")
	ErrCastingWorkload          = errors.New("casting workload")
	ErrMockError                = errors.New("mock error")
	ErrTooManyRequests          = errors.New("too many requests")
)

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
