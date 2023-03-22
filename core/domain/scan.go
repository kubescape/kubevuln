package domain

import wssc "github.com/armosec/armoapi-go/apis"

type ScanIDKey struct{}
type TimestampKey struct{}
type WorkloadKey struct{}

// ScanCommand is a proxy type for wssc.WebsocketScanCommand used to decouple business logic from implementation
// it might evolve into its own struct at a later time
type ScanCommand wssc.WebsocketScanCommand
