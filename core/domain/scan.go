package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/docker/docker/api/types"
)

const (
	AttributeUseHTTP = armotypes.AttributeUseHTTP
	AttributeSkipTLSVerify = armotypes.AttributeSkipTLSVerify
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
