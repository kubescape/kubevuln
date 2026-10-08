package domain

import (
	"context"
	"errors"
)

var (
	ErrHostInventoryPending     = errors.New("host inventory pending")
	ErrHostInventoryUnavailable = errors.New("host inventory unavailable")
)

const (
	HostInventoryToolNameAnnotationKey        = "kubescape.io/host-inventory-tool-name"
	HostInventoryUIDAnnotationKey             = "kubescape.io/host-inventory-uid"
	HostInventoryResourceVersionAnnotationKey = "kubescape.io/host-inventory-resource-version"
)

type hostInventoryReadyKey struct{}

// WithHostInventoryReady installs the atomic inventory acceptance gate for a scan.
func WithHostInventoryReady(ctx context.Context, accept func() error) context.Context {
	return context.WithValue(ctx, hostInventoryReadyKey{}, accept)
}

// AcceptHostInventory must succeed before scanning or publishing a ready inventory.
func AcceptHostInventory(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if accept, ok := ctx.Value(hostInventoryReadyKey{}).(func() error); ok && accept != nil {
		return accept()
	}
	return nil
}

type hostInventoryFailureReporterKey struct{}

// WithHostInventoryFailureReporter lets a validated host scan register the
// platform report the controller owns when its inventory wait budget expires.
func WithHostInventoryFailureReporter(ctx context.Context, register func(func(context.Context, error))) context.Context {
	return context.WithValue(ctx, hostInventoryFailureReporterKey{}, register)
}

// RegisterHostInventoryFailureReporter binds validated host metadata to a
// terminal inventory report. The reporter receives a fresh, uncanceled context;
// it must not reuse the cancelable inventory lookup context.
func RegisterHostInventoryFailureReporter(ctx context.Context, report func(context.Context, error)) {
	if register, ok := ctx.Value(hostInventoryFailureReporterKey{}).(func(func(context.Context, error))); ok && register != nil {
		register(report)
	}
}

// AcceptHostInventoryFailure atomically ends inventory waiting for a terminal
// lookup or validation failure. It uses the same arbitration as readiness, but
// authorizes only failure reporting, never scanning or result publication.
func AcceptHostInventoryFailure(ctx context.Context) error {
	return AcceptHostInventory(ctx)
}
