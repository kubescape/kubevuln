package domain

import (
	"context"
	"time"
)

type ScanState string

const (
	ScanStateQueued    ScanState = "queued"
	ScanStateRunning   ScanState = "running"
	ScanStateSucceeded ScanState = "succeeded"
	ScanStateFailed    ScanState = "failed"
	ScanStateAbandoned ScanState = "abandoned"

	ScanReasonShutdownAbandoned = "shutdown_abandoned"
)

type ScanStatus struct {
	JobID      string     `json:"jobID"`
	Endpoint   string     `json:"endpoint"`
	State      ScanState  `json:"state"`
	Phase      string     `json:"phase"`
	Reason     string     `json:"reason,omitempty"`
	AcceptedAt time.Time  `json:"acceptedAt"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	UpdatedAt  time.Time  `json:"updatedAt"`
}

type scanPhaseUpdaterKey struct{}

func WithScanPhaseUpdater(ctx context.Context, update func(string)) context.Context {
	return context.WithValue(ctx, scanPhaseUpdaterKey{}, update)
}

func UpdateScanPhase(ctx context.Context, phase string) {
	if phase == "" {
		return
	}
	if update, ok := ctx.Value(scanPhaseUpdaterKey{}).(func(string)); ok && update != nil {
		update(phase)
	}
}
