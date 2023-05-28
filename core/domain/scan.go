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
	ErrMissingImageID   = errors.New("missing imageID")
	ErrMissingScanID    = errors.New("missing scanID")
	ErrMissingTimestamp = errors.New("missing timestamp")
	ErrMissingWorkload  = errors.New("missing workload")
	ErrMockError        = errors.New("mock error")
	ErrTooManyRequests  = errors.New("too many requests")
)

type ScanIDKey struct{}
type TimestampKey struct{}
type WorkloadKey struct{}

type ScanCommand struct {
	Credentialslist []types.AuthConfig
	ImageHash       string
	InstanceID      string
	Wlid            string
	ImageTag        string
	JobID           string
	ContainerName   string
	LastAction      int
	ParentJobID     string
	Args            map[string]interface{}
	Session         Session
}

type Session struct {
	JobIDs []string
}
