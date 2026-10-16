package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// One process-wide gate bounds storms independently of workload cardinality.
// No identifiers or attacker-controlled strings are retained as dedup keys.
var diagnosticGate = &gate{}
var suppressed atomic.Int64

// Suppressed returns the cumulative diagnostic records omitted by the storm gate.
func Suppressed() int64 { return suppressed.Load() }

type gate struct {
	mu   sync.Mutex
	next time.Time
}

func (g *gate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.next) {
		return false
	}
	g.next = now.Add(time.Minute)
	return true
}

// ScanDiagnostic emits at most one slow/failure diagnostic per process/minute.
// Metrics are recorded by the caller regardless of this gate or trace sampling.
func ScanDiagnostic(ctx context.Context, start time.Time, failed bool) {
	elapsed := time.Since(start)
	if !failed && elapsed < 30*time.Second {
		return
	}
	if !diagnosticGate.allow(time.Now()) {
		suppressed.Add(1)
		return
	}
	outcome := "slow"
	if failed {
		outcome = "failed"
	}
	ctx, s := otel.Tracer(Scope).Start(ctx, "kubevuln.scan.diagnostic", trace.WithTimestamp(start), trace.WithAttributes(attribute.String("outcome", outcome)))
	defer s.End()
	var r log.Record
	r.SetTimestamp(time.Now())
	r.SetSeverity(log.SeverityWarn)
	r.SetBody(attribute.StringValue("scan requires investigation"))
	r.AddAttributes(attribute.String("outcome", outcome), attribute.Float64("duration_seconds", elapsed.Seconds()))
	otel.GetLoggerProvider().Logger(Scope).Emit(ctx, r)
}
