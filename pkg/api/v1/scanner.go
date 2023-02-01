package v1

import (
	"errors"
	"fmt"

	wssc "github.com/armosec/armoapi-go/apis"
)

// ScannerService contains the methods of the user service
type ScannerService interface {
	Ready() bool
	NewDbCommand(wssc.DBCommand) error
}

type scannerService struct{}

func NewScannerService() ScannerService {
	return &scannerService{}
}

func (s scannerService) Ready() bool {
	return true
}

func (s scannerService) NewDbCommand(command wssc.DBCommand) error {
	for op := range command.Commands {
		switch op {
		case "updateDB":
			return s.updateDb()
		default:
			return fmt.Errorf("unsupported command %s", command)
		}
	}
	return errors.New("no command given")
}

func (s scannerService) updateDb() error {
	return nil
}
