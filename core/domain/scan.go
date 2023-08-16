package domain

import (
	"errors"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/docker/docker/api/types"
)

const (
	AttributeUseHTTP       = armotypes.AttributeUseHTTP
	AttributeSkipTLSVerify = armotypes.AttributeSkipTLSVerify
)

var (
	ErrExpectedError    = errors.New("expected error")
	ErrInitVulnDB       = errors.New("vulnerability DB is not initialized, run readiness probe")
	ErrIncompleteSBOM   = errors.New("incomplete SBOM, skipping CVE scan")
	ErrInvalidScanID    = errors.New("invalid scanID")
	ErrMissingImageInfo = errors.New("missing image information")
	ErrMissingScanID    = errors.New("missing scanID")
	ErrMissingTimestamp = errors.New("missing timestamp")
	ErrCastingWorkload  = errors.New("casting workload")
	ErrMockError        = errors.New("mock error")
	ErrTooManyRequests  = errors.New("too many requests")
)

type ScanIDKey struct{}
type TimestampKey struct{}
type WorkloadKey struct{}

type ScanCommand struct {
	Credentialslist    []types.AuthConfig
	ImageHash          string
	ImageSlug          string
	InstanceID         string
	Wlid               string
	ImageTag           string
	ImageTagNormalized string
	JobID              string
	ContainerName      string
	LastAction         int
	ParentJobID        string
	Args               map[string]interface{}
	Session            Session
}

type Session struct {
	JobIDs []string
}
