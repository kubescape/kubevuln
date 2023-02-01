package v1

import (
	"errors"

	wssc "github.com/armosec/armoapi-go/apis"
)

// CVEService contains the methods of the cve service
type CVEService interface {
	New(wssc.WebsocketScanCommand) error
}

// CVERepository is what lets our service do db operations without knowing anything about the implementation
type CVERepository interface {
	StoreCVE(CVE) error
}

type cveService struct {
	storage CVERepository
}

func NewCVEService(cveRepo CVERepository) CVEService {
	return &cveService{storage: cveRepo}
}

func (c *cveService) New(newScan wssc.WebsocketScanCommand) error {
	if newScan.ImageHash == "" {
		return errors.New("missing imageHash")
	}
	return nil
}
