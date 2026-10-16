# Operational telemetry

Kubevuln exports operational metrics, deliberately gated diagnostic spans, and
structured warning logs. This is separate from security findings and the sandbox
`OTEL_EVENTS_EXPORTER_ENDPOINT`, which this integration never reads or modifies.
See the shared [current implementation snapshot](https://github.com/armosec/shared-designs-and-docs/blob/docs/otel-implementation-reality/projects/agent-telemetry-system/research/high-level-requirements.md#current-implementation-october-16-2026)
for system context. Its **5–15 KB/agent/hour is an unvalidated planning target**,
not an enforced upload quota or a measured kubevuln budget.

For bounded live evidence from armo-dev-stage, see
[Stage validation](TELEMETRY_STAGE_VALIDATION.md).

## Support questions

- Are scans finishing, failing to pull/authenticate, timing out, or failing to upload?
  Compare completion rates and bounded failure reasons with retry/fallback counts.
- Is demand exceeding worker capacity? Compare queue depth, scan latency, rejections,
  goroutine count, and heap use. Queue growth with rising latency warrants capacity
  investigation; more retries can instead indicate an upstream incident.
- Is accepted work stalled? The oldest-progress gauge covers tracked queued/running
  jobs. A rising value with no completions points to stalled work; inspect
  `/v1/diagnostics` and the existing authenticated deployment's local logs.
- Is a failure storm hiding individual diagnostics? The suppression counter shows
  how many diagnostic pairs the rate gate omitted. Aggregate outcome metrics are
  unaffected by sampling and diagnostic suppression.
- Can an upstream request be correlated? W3C trace context is extracted on HTTP
  ingress, retained across background jobs, injected on backend report POSTs, and
  propagated over scanner gRPC. A gated diagnostic retains that parent context.

## Initialization and configuration

Each process initializes providers once before successful-startup logger and
instrument construction. Discovery completes first. HTTP uses its resolved account
(`/etc/credentials/account`, then `accountID`/`ACCOUNTID`) and access key from
`/etc/credentials/accessKey`. Scanner uses those same credential files if mounted.
Both pass credentials through `otelsetup.ProviderConfig`; shared setup authenticates
trace/log RPCs, and the component's metric reader applies the same header policy.
Credentials never become telemetry attributes or diagnostic messages.

Operational export is opt-in through an explicit endpoint or the `metrics` field
of discovery using an explicitly configured `API_URL`. With neither, discovery
makes no HTTP request and all OTLP signals stay disabled; there is no hardcoded
cloud discovery fallback. Local Prometheus and normal console logging remain
available. Missing telemetry credentials are quiet and never block initialization
or processing. An explicit collector (base, legacy, or per-signal endpoint) works
without credentials; authentication headers are added only when an access key is
present. This does not change the existing account requirement for HTTP backend
reporting: OSS operation without that backend uses `keepLocal`.

Unconfigured trace/log providers are concrete no-ops, and unconfigured metrics
have no OTLP reader. Explicitly empty base configuration suppresses discovery and
the legacy endpoint while still allowing nonempty per-signal overrides. The
precedence and opt-out rules in the table below apply equally to OSS collectors.

`go-logger v0.0.35` is required: v0.0.33's unused-before-this-change OTEL ring-buffer
package does not compile against the repository's existing OTel log API v1.47.0.
The gRPC exporters are aligned with the existing OTel SDK v1.47.0 (logs v0.23.0).
No shared-library source is changed.

| Setting | Effective behavior |
| --- | --- |
| Discovery source | Existing backend `servicediscovery/v3` client, `API_URL`, response `metrics` field; one request, at most 3 seconds, response at most 1 MiB; nonfatal, no retries |
| Discovery eligibility | Base endpoint must be **unset**; skip for HTTP `keepLocal`; no default production API host when `API_URL` is absent |
| Endpoint precedence | `OTEL_SDK_DISABLED=true` or base `disable` opts out of all operational signals; otherwise explicit base (including empty) wins, then legacy `OTEL_COLLECTOR_SVC` if present, then discovery |
| Signal overrides | Nonempty `OTEL_EXPORTER_OTLP_{METRICS,TRACES,LOGS}_ENDPOINT` overrides base; empty signal values fall back to base, matching shared setup; explicit base empty prevents discovery but permits nonempty signal overrides |
| Normalization / protocol | Scheme-less **discovered** endpoint gets `https://`; explicit schemes preserved. Explicit/legacy bare `host:port` retains shared plaintext gRPC semantics. OTLP/gRPC only; `OTEL_EXPORTER_OTLP_PROTOCOL` does not select HTTP here |
| Service identity | HTTP `kubevuln`; sidecar `kubevuln-sbom-scanner`; version `RELEASE` |
| Resource attributes | HTTP cluster/namespace from loaded config; scanner `CLUSTER_NAME`/`NAMESPACE`; optional `POD_NAME`/`NODE_NAME` for both. Account is an auth header, not a metric dimension |
| Metric interval | Default `OTEL_METRIC_EXPORT_INTERVAL=60000` ms; explicit SDK override preserved; chosen to show backlog/stalls within minutes in a long-running scan service |
| Metric timeout / retries | Reader default `OTEL_METRIC_EXPORT_TIMEOUT=3000` ms; metric RPC hard timeout 3 seconds and retries disabled; no durable queue or replay; cumulative counters can recover at the next successful collection |
| Trace sampler | Default `OTEL_TRACES_SAMPLER=traceidratio`, `OTEL_TRACES_SAMPLER_ARG=0.1`; explicit SDK overrides preserved. Ratio sampling applies even to remote sampled parents, so incoming sample flags cannot bypass the local sampling choice |
| Exported log level | Hard export-level **warn and above**, and only the reviewed operational scope/message/attribute allowlist; independent of local `KS_LOGGER_LEVEL`/logger format |
| Compression | Default `OTEL_EXPORTER_OTLP_COMPRESSION=gzip`; SDK per-signal compression overrides remain effective |
| Trace/log buffers | Default BSP/BLRP queue 256 records, export batch 64, export timeout 3000 ms; nonblocking recording with drops when full; standard environment overrides remain effective |
| Trace/log retry | Shared exporters' SDK retry loop is bounded by the default 3-second overall RPC timeout and processor timeout; standard explicit timeout overrides can change this |
| Deduplication / rate limit | One **process-wide** slow/failure/rejection diagnostic pair per 60 seconds, measured from previous admission; a constant key, one timestamp, no workload cache; rest counted as suppressed |
| Slow path | Completed scan taking at least 30 seconds, failed completion, or validation/admission rejection; all ordinary completions use aggregate metrics only |
| Shutdown | Fresh background context, bounded 5-second flush for shared trace/log providers; metric provider has a separate bounded shutdown after worker draining |

Standard environment overrides are operator controls, **not enforced ingest quotas**.
Invalid explicitly supplied SDK settings use SDK fallback/error behavior; check the
actual environment when interpreting volume. Changing sampler to `always_on`
does not bypass the diagnostic creation gate. Neither batching nor retention,
authentication, or container memory limits enforce an ingest budget.

### Shared provider compatibility

Shared `otelsetup.InitProviders` accepts no extra metric reader, histogram view,
or export filter. Kubevuln therefore reuses it for trace/log setup, authentication,
resources, and shutdown, while keeping **one existing metric provider** with both
Prometheus and OTLP readers. During serial startup only, the adapter resolves
trace/log endpoints and temporarily masks base/metric/legacy endpoints to prevent
shared setup constructing a second metric provider. Environment presence and values
are restored before instruments, loggers, and application goroutines are built.

The shared debug replay HTTP listener is disabled during initialization, including
when local `KS_LOGGER_LEVEL=debug`; that level is restored for local logging.
Ring-buffer replay would bypass the diagnostic rate limit. The shared 7,500-record
buffer still exists when logs are enabled, but it sees only admitted safe records
and has no component-exposed flush route. Existing application logger output stays
local; it is not also exported. Other instrumentation scopes, including legacy
per-scan spans and third-party spans, receive no-op tracers. This intentionally
replaces unrestricted historical spans rather than adding another exporter.

## Instrumentation inventory

Metrics retain the existing `/metrics` inventory and names on HTTP `:8080` and
scanner `METRICS_ADDR` (default `:8081`). OTLP sends the same instruments from the
same provider; configuring both backend Prometheus scraping and OTLP ingestion can
still duplicate stored data and must be reconciled by the deployment owner.

| Instruments | Bounded dimensions / meaning |
| --- | --- |
| `kubevuln_scans_completed_total`, `kubevuln_scan_duration_seconds` | Fixed endpoint, success/partial/error outcome, known `scanfailure` reason or `unexpected_error`; no job/workload/image identity |
| `kubevuln_scan_rejections_total` | Fixed endpoint and invalid request / queue full / duplicate job / upstream throttle reason |
| `kubevuln_worker_pool_queue_depth` | Unlabeled waiting jobs; running jobs excluded |
| `kubevuln_work_oldest_progress_age_seconds` | Unlabeled maximum age since progress among tracked active jobs; terminal jobs excluded |
| `kubevuln_telemetry_diagnostics_suppressed_total` | Unlabeled diagnostic pairs omitted by rate gate |
| `kubevuln_scan_fallbacks_total` | Component, fallback category/strategy/outcome constants |
| `kubevuln_scan_source_resolution_total` | Component and first-pass/fallback-assisted outcome |
| `kubevuln_registry_auth_cache_total` | Credential provider strategy and hit/miss/coalesced; no credentials or registry URL |
| `kubevuln_singleflight_hits_total` | Fixed operation target |
| `kubevuln_retry_attempts_total` | Fixed operation and attempt/success/exhausted |
| `kubevuln_exceptions_{degraded,matched,expired}_total`, `kubevuln_exceptions_active` | Degraded/active unlabeled; matched/expired allowlist `SecurityException`, `ClusterSecurityException`, or `unknown` |
| `kubevuln_temp_dir_sweep_removed_total` | Component only |
| `kubevuln_runtime_heap_bytes`, `kubevuln_runtime_goroutines` | Unlabeled runtime samples; heap objects are not total container RSS |

Histogram boundaries, seconds: **0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300,
600, 1800**. Each reader caps attribute sets at **256 per instrument**, including
an overflow aggregation; dimensions at call sites remain fixed enums. Histogram
buckets multiply stored series, and resource/tenant attributes multiply fleet
cardinality. The cap is not a fleet-wide bound or a byte quota.

HTTP lifecycle spans: `kubevuln.startup`, `kubevuln.shutdown`; scanner lifecycle
spans: `kubevuln.scanner.startup`, `kubevuln.scanner.shutdown`. These mark startup
and shutdown entry, not readiness or complete drain duration.
`kubevuln.scan.diagnostic` uses the completion's start/end timestamps and a single
`outcome=slow|failed` attribute. It is created retrospectively only after the gate
admits a completion or rejection; it does not generate child spans for every internal operation.

The corresponding structured log body is always `scan requires investigation`;
only `outcome` and numeric `duration_seconds` attributes can export. The SDK
supplies trace/span IDs, including for unsampled traces (a correlated trace may
therefore have no stored span). Raw errors, payloads, URLs, workload/tenant/job IDs,
credentials, arbitrary application records, and caller-supplied attributes are
excluded. There is no generic production log forwarding switch in this component.

## Troubleshooting examples

Prometheus-style expressions (adjust OTLP backend name translation if needed):

```promql
# Completion throughput and classified failures.
sum by (endpoint, outcome, reason) (rate(kubevuln_scans_completed_total[5m]))
# Backlog pressure and admission drops.
kubevuln_worker_pool_queue_depth
sum by (reason) (rate(kubevuln_scan_rejections_total[5m]))
# End-to-end scan latency distribution, including failures.
histogram_quantile(0.95, sum by (le) (rate(kubevuln_scan_duration_seconds_bucket[5m])))
# Work with no progress for over five minutes; correlate with diagnostics/configured timeout.
kubevuln_work_oldest_progress_age_seconds > 300
# A storm that exceeded diagnostic allowance; metrics retain its magnitude.
rate(kubevuln_telemetry_diagnostics_suppressed_total[5m]) > 0
```

Search logs for the constant diagnostic body, then follow its trace ID where
sampled. Use bounded outcome/reason metrics to distinguish registry credentials,
missing images, CVE matching, storage, and upload failures. Local application logs
remain the detailed fallback; exported records deliberately contain no raw errors.
For no telemetry, check explicit opt-out/empty base, `API_URL`, credentials mounts,
per-signal overrides, collector connectivity, and whether the selected image
contains this integration. No discovery retry occurs after startup failure.

## Deployment configuration checked

This repository contains Dockerfiles, test configuration, and documentation
examples, but **no packaged Helm chart or production Pod manifest**. No deployment
configuration was changed in this implementation.

| Mode | Checked-in availability / required external configuration |
| --- | --- |
| HTTP in-process | Image sets `RELEASE` and entrypoint. `/etc/config/clusterData.json` supplies cluster/namespace/account fallback; For authenticated backend export, mount `/etc/credentials/{account,accessKey}` externally. `API_URL` is optional and not set in the image |
| HTTP + scanner sidecar | Same image, `sbom-scanner` command. Existing documented socket/shared `/tmp`/distinct metrics ports still apply. For authenticated backend telemetry, both containers need their own environment and credential mount; inheritance from the main container is not automatic. Scanner reads no HTTP cluster config, so resource values require `CLUSTER_NAME`/`NAMESPACE` |
| Static `services.json` / `clusterData.json` backend URLs | Functional backend startup can work without `API_URL`. Those static URLs do not imply a discovery API URL; telemetry discovery skips when absent. Supply an explicit OTLP endpoint or `API_URL` externally |
| Local `keepLocal` HTTP | No backend discovery; explicit OTLP endpoint can target a local collector without credentials. Without endpoint there is only Prometheus. Scanner has no `keepLocal` configuration; unset `API_URL` or explicit opt-out prevents discovery there |
| Offline DB image | Separate DB-serving image; does not run these binaries or initialize their providers |
| CLI | Placeholder command exits; no telemetry integration |

Production chart owners must verify mounts, account/access-key availability,
`API_URL`, and resource environment for **both** containers before rollout. The initial implementation audit inspected source and examples; the subsequent
[stage validation](TELEMETRY_STAGE_VALIDATION.md) inspected a running deployment
without changing chart source.

## Validation and measurements

`go test -v ./internal/telemetry -run TestExportVolume` runs SDK exporters against
an in-process loopback OTLP/gRPC collector. No production endpoints are contacted.
The fixture records fixed-dimension scan counter/histogram updates plus two runtime
gauges, then flushes once. Trace sampling is explicitly `always_on` to test the
creation gate independently of sampling; gzip is enabled. Runtime/resource values,
IDs, and timestamps can slightly change compressed lengths between runs.

One October 16, 2026 local run:

| Synthetic completions in one window | Metric points | Spans | Logs | Protobuf bytes, metrics/traces/logs | Compressed gRPC payload bytes, all signals |
| --- | ---: | ---: | ---: | --- | ---: |
| 10 successes | 4 | 0 | 0 | 970 / 0 / 0 | 526 |
| 10 failures | 4 | 1 | 1 | 966 / 431 / 465 | 1242 |
| 10,000 failures | 4 | 1 | 1 | 966 / 431 / 465 | 1255 |

Counts are exported metric **points/attribute sets**, not expanded backend
histogram bucket series. Compressed sizes come from gRPC `InPayload.WireLength`
(including its five-byte message prefix), excluding HTTP/2, TLS, connection setup,
and collector processing. They are measurements of this synthetic fixture,
**not representative bytes per agent/hour**. The full real instrument inventory,
queue callbacks, source kinds, fallback combinations, pod count, ingestion-side
span metrics, and repeated periodic exports require a representative workload
measurement before estimating fleet costs.

Repository checks: `go test ./...`, targeted race tests, `go vet ./...`, branch
`make lint`, and CGO-disabled builds of both binaries passed. `make test`
(the Docker fixture variant) failed in three Grype DB tests because the pinned
fixture container exited with code 1 before readiness. The unchanged HEAD
`db7ee4f` reproduced the same failure with
`go test -tags dockerfixture ./adapters/v1 -run '^Test_grypeAdapter_DBVersion$' -count=1`
in a separate temporary checkout. This remains an explicit environment/fixture
validation gap; it is not counted as a passing check.

Additional tests cover endpoint presence/empty/opt-out/legacy precedence, per-signal
routing, TLS normalization, missing fields, discovery errors/cancellation/body
bounds, safe log severity/shape/scope, concurrent 10,000-call gating, histogram
boundaries, auth headers, HTTP/gRPC propagation, stalled-work age, and recording and
bounded shutdown during backend outage, and sidecar final metric flush before
its first periodic interval.

## Limitations and follow-ups

- No byte quota or fleet/tenant ingest quota is implemented. Representative image
  scans, sustained traffic over hours, changing workload populations, full histogram
  series, and backend ingestion costs remain unmeasured. Collector capacity and
  tenant admission controls require separate ownership; they were not changed.
- Diagnostic allowance is process-local and resets on restart. Replicas and repeated
  restarts increase fleet volume; SDK sampler/environment overrides also change it.
  A single gate can suppress a different failure class during a storm; use metrics
  for unbiased counts. Rejections use the same gate; abandoned jobs have no individual diagnostic.
- Oldest-progress metrics exclude requests without job IDs. It measures time since
  a phase update, not proof of deadlock; a legitimate long phase can trigger it.
- Existing scan admission defaults to an unbounded application queue unless
  `maxQueueDepth` is positive. Telemetry queues are independently bounded, but this
  change does not impose a new application admission policy.
- Exporter queue drops are not exposed by the shared API as counters. Diagnostic
  suppression and application rejection metrics do not measure exporter losses.
  Backends may miss interval data during outage; there is no disk spool.
- Heap/goroutine metrics are not process CPU or container RSS measurements. Use the
  deployment's container metrics for CPU/RSS; no second runtime instrumentation
  package or broad host/resource discovery is started here.
- Broader trace trees would need reviewed safe attributes and additional volume gates.
  Context preservation is tested on explicit backend report POSTs and scanner RPCs;
  existing shared backend client methods that do not accept context cannot carry it.
- Shared library follow-up: injectable readers/views, log filters/processors, debug
  listener controls, and exporter-drop visibility would remove the startup-only
  environment adapter. No changes to that library, discovery contracts, collector,
  or deployment configuration were made here.
- Deployment grace periods must cover additive drain/flush budgets: HTTP can use
  5 s HTTP shutdown + default 20 s worker drain + 5 s metrics + 5 s trace/log
  (35 s); scanner can use 20 s RPC drain + 20 s metrics HTTP drain + 5 s
  metrics + 5 s trace/log (50 s). The Kubernetes 30-second default cannot
  guarantee all final flushes in the worst case. Assess externally; no manifest
  was changed here.
- Bounded stage authentication/routing, cadence, burst gates and final metric flush
  were subsequently [verified live](TELEMETRY_STAGE_VALIDATION.md). Production
  rollout, collector quotas and representative fleet bytes remain unverified.
  Code tests, synthetic sizes and this one stage run do not establish those claims.

### OSS activation regression coverage

Local mock-collector tests cover unauthenticated base, legacy, and each individual
signal endpoint, and confirm absent credential headers. Unconfigured, explicit
empty, and SDK-opt-out cases export no signals. Fresh-process tests exercise
no-op trace/log providers and missing metric readers, preserve structured console
output, and cover absent endpoints, failed discovery, opt-out, and metrics-only
configuration. An intercepted HTTP transport verifies absent `API_URL` does not
make a discovery request or use a fallback. These are local code tests, not new
live deployment observations.
