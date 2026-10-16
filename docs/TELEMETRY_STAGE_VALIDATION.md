# Kubevuln live stage validation — October 16, 2026

PR [#1184](https://github.com/kubescape/kubevuln/pull/1184) was tested temporarily in
**armo-dev-stage**, with telemetry received by **SigNoz in that same cluster**.
This was not a workstation-local collector test. All cluster resource commands
used the explicit stage context; no global context switch or production change
was made. This report separates source/test guarantees, running deployment
configuration, live observations, and unmeasured requirements.

See [Operational telemetry](OPERATIONAL_TELEMETRY.md) for the complete instrument
inventory and controls, and its link to the shared current-implementation document.
**5–15 KB/agent/hour remains an unvalidated planning target, not an enforced quota
or a measured rate for this component.**

## Tested code and environment

| Item | Evidence |
| --- | --- |
| Tested source | `f194c0dbaa336d0ad7f88eebe4f8cc03529a2efb`, including the bounded rejection diagnostic fix on top of `e34ec78` |
| Cluster | `armo-dev-stage`, namespace `kubescape`, one replica with HTTP and scanner containers; mixed amd64/arm64 nodes |
| Original/restored images | Both containers: `quay.io/kubescape/kubevuln:v0.3.546` |
| Test version | `stage-otel-20261016T104430Z-warm` |
| Multi-architecture image | `quay.io/matthiasb_1/kubevuln:stage-otel-20261016T104430Z-warm`, index digest `sha256:b98836db703424d4a1d83410432ff797efe797a9e21c94249d1989ae4f9fd516` |
| Build | Both binaries cross-built with CGO disabled for linux/amd64 and linux/arm64, then packaged with the repository's distroless base; anonymous manifest access verified. The available kubescape registry credential could not push, so the accessible personal namespace was used; no release tag overwritten |
| Executed architecture | The live test Pod ran on arm64; amd64 was cross-built/published but not live-executed |
| Test services | `kubevuln` and `kubevuln-sbom-scanner`, both with the unique version above |
| Discovery | Existing `API_URL=https://api-dev.armosec.io`, v3 service discovery `metrics=otel.dev-stage.armosec.io:443`, normalized to `https://otel.dev-stage.armosec.io:443` |
| Authentication | Existing account/access-key Secret mounted by reference; shared `ProviderConfig` header injection. The live receiver uses `armoauth`; `armotenant` drops missing auth context. Received metrics carried nonempty `tenant.id`; credential/tenant values were not published |
| Backend | Existing two-replica `armo-signoz-otel-collector:v0.4.0`, SigNoz v0.125.0 and ClickHouse v25.5.6 in namespace `signoz`; queried through the Kubernetes API, not a local SigNoz |

The saved running Deployment had a `Recreate` strategy and a 30-second termination
grace period. The main container already had `API_URL` and `/etc/credentials`.
The scanner had neither. Temporary changes were confined to this Deployment:
test images, unique `RELEASE`, a measurement annotation, and the scanner's existing
Secret volume mount plus API/cluster/namespace environment. No Secret contents,
ConfigMap, collector, other component, chart source, or discovery contract changed.
The scanner mount/environment remain a **deployment-owner follow-up** for rollout.

## Effective controls

No OTEL settings were overridden during normal, burst, or sampler observations.
The base endpoint, legacy alias, and per-signal endpoints were absent from the
Pod specification, so the received signals used backend discovery. Opt-out,
explicitly empty versus unset, explicit endpoint precedence and per-signal overrides
were code-tested; they were not toggled live in this run.

| Setting | Effective configuration / evidence boundary |
| --- | --- |
| Metric export | Default 60000 ms; observed cadence below |
| Trace sampling | Default `traceidratio`, argument `0.1`; deterministic positive/negative trace-ID probes below, not a statistical estimate of the fleet sampling fraction |
| Exported logs | Warn+ plus scope/message/attribute allowlist; local logger format/level retained |
| Compression | Default gzip, verified by local receiver tests and unchanged configuration; encrypted live wire compression was not independently measured |
| Histogram | Seconds: `0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800`; backend expansion observed |
| Creation gate | One process-wide diagnostic pair per 60 seconds; slow completed scans at least 30 seconds, failed completions and rejections share the gate; suppression counter remains unsampled |
| Buffers / retry | SDK trace/log queues 256, batches 64, default RPC/processor timeout 3 s; metric retry disabled with hard 3 s RPC timeout; configuration inspected and offline outage behavior tested, no live collector outage induced |
| Shutdown | Bounded separate metric and shared trace/log flushes; final metric exports observed below. This does not establish that every worst-case drain fits the original 30-second Pod grace period |
| Event stream | `OTEL_EVENTS_EXPORTER_ENDPOINT` untouched and not used by operational providers |

Cluster/namespace resources came from the existing main configuration and temporary
scanner environment. Pod/node resource environment was absent; this run does not
claim populated pod/node resource attributes. Service/version filtering isolated
the test. No workload, image, request, or tenant values appeared in application
metric dimensions; authenticated tenant identity is a separate collector resource.

## Preparation, startup and restoration safety

The original complete Deployment specification was saved privately before mutation.
A 15-minute watchdog was armed before each temporary change. Restoration used
JSON patch tests for the original Deployment UID, measurement identity, and exact
owned image/environment/mount values; it restored only those fields. It would
refuse conflicting changes rather than overwrite them. Readiness supervision
restored on startup failure or a bounded startup timeout.

The read-only SigNoz baseline found no metrics, spans, or logs for these two service
names in the preceding 30 minutes. The collector Deployment/configuration and
meter schema were inspected before the test.

An initial attempt (`stage-otel-20261016T104430Z`, index digest
`sha256:f54dbbed9a4ac60cf66c6ea7463290bd1edec5e112e46c0a608bd71d4694d5ed`)
received authenticated metrics but was stopped conservatively while the main
container was still warming its CVE database. **No test requests were sent**.
The restored original also required approximately 3 minutes 20 seconds of cold
DB warm-up; it became ready with exact original-spec equality at **10:54:58.782 UTC**.
This did not establish an OTEL startup regression. The wait was consistent with cold database initialization using an ephemeral
cache; transfer/decompression/DB-loading time was not separately attributed.
Readiness therefore had to be checked before
starting the traffic experiment; no readiness bypass was used.

The retry was patched at **10:56:01 UTC**, and both containers were ready at
**10:59:16.581 UTC**, without restarts. Liveness, readiness and diagnostics returned
HTTP 200. Diagnostics confirmed sidecar mode and a loaded CVE database. The healthy
normal observation started at **10:59:39 UTC**.

## Normal and burst measurements

The table reports actual ingested values for the retry version. Completion,
rejection and suppression counters are cumulative; queue depth and oldest-progress
age are point-in-time gauges. Stored-series counts are backend observations.
The two healthy default collections were **11:00:06.002** and **11:01:06.003 UTC**:
**60.001 seconds** apart. Scanner collections were offset by approximately 0.67 s
at 11:00:06.674 and 11:01:06.674 UTC, exactly 60.000 seconds apart. Startup collections are not presented as
healthy normal activity.

| Observation | Normal 1 | Normal 2 | Pre-burst | During burst | Completed burst | Final shutdown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Main collection UTC | 11:00:06.002 | 11:01:06.003 | 11:02:06.003 | 11:03:06.002 | 11:04:06.003 | 11:06:04.580 |
| Successful organic `scanCP` completions | 20 | 28 | 28 | 32 | 48 | 86 |
| Deliberate validation rejections | 0* | 0* | 1 | 837 | 1001 | 1002 |
| Suppressed diagnostic pairs | 0 | 0 | 0 | 835 | 999 | 999 |
| Waiting queue depth | 7 | 0 | 0 | 1 | 16 | 0 |
| Oldest tracked progress age, seconds | 52.918 | 0 | 0 | 12.981 | 38.995 | 0 |
| Application stored series | 26 | 26 | 27 | 27 | 27 | 27 |

`*` No rejection time series existed before its first observation. The counts of
1001 and 1002 include one calibration request and then one separate sampler probe.
Organic successful scans continued independently of injected traffic; the injected
requests never became queued or completed scans. Queue/progress snapshots are not
instantaneous peaks or proof of a deadlock.

At the second normal collection, the scan histogram held 28 observations, sum
**72.5113 s**, minimum **0.4317 s**, maximum **4.5463 s** (derived mean **2.5897 s**).
At shutdown it held 86 observations, sum **246.2267 s**, maximum **6.0022 s**.
This is execution timing for the instrumented profile-scan workflow, excluding
waiting-queue delay; it is not latency for every possible scan mode. No error
completion/fallback/retry series was observed in this run. Lack of such observations
does not validate those failure paths; targeted local tests remain their evidence.

### Validation boundary and exact traffic

The injected request was `POST /v1/generateSBOM`, content type `application/json`,
body `{}`. `ValidateGenerateSBOM` returns `ErrMissingImageInfo` before `admitJob` or
`runTrackedScan`: no target resolution, queue admission, image pull, SBOM/CVE work,
storage write, or reporting occurs. Only fixed local validation logging, bounded
operational diagnostics and the rejection counter run. The test never submitted
credentials or sensitive payloads.

Before this verification, rejections counted metrics but emitted no operational
diagnostic, preventing safe live correlation/gate verification on this path.
Commit `f194c0d` routes them through the existing shared gate; its regression checks
1000 rejection increments, bounded suppression and no scan-completion metric.
The gate allowance, safe exported attributes and normal defaults are unchanged.

- Calibration: **11:01:36.692–11:01:36.974 UTC**, one request, HTTP 400.
- Burst: **11:02:51.452–11:03:08.812 UTC**, exactly **1000 requests**, all **1000
  HTTP 400**, **17.3598 s**, at most 16 concurrent requests. **Zero accepted for
  scan work; 1000 synchronous validation completions**. Client latency over the
  Kubernetes port-forward was p50 **272.3 ms**, p95 **282.6 ms**; this includes
  network/forwarding and is not server processing time or telemetry overhead.
- The collection at **11:03:06.002** happened before all responses finished and
  correctly held only 837 cumulative rejections. The next complete collection
  showed the full delta: **+1000 rejections, +999 suppressed pairs, +1 exported
  warning and +1 diagnostic span**, with no application or related series growth.

### Traces, logs and sampling

Every burst request carried the same synthetic sampled W3C parent. The lower
trace-ID bits were deliberately chosen to be included by the unchanged 10% ratio
sampler, so sampling cannot explain away the other 999 omitted spans: the creation
gate prevented them. Calibration and burst each emitted `kubevuln.scan.diagnostic`
with only `outcome=failed`; both preserved the supplied trace ID and parent span ID.

At **11:04:33.689 UTC**, after the gate reopened, a separate HTTP 400 probe used
an all-`f` trace ID with incoming sampled flag `01`. That ID is excluded by the
ratio sampler. It emitted one warning with `trace_flags=0` and **no stored span**:
the incoming flag did not override local sampling. These deliberately chosen IDs
exercise decision boundaries; they do not measure a random 10% sampling rate.

The final totals were **two diagnostic spans and three warning records**. Normal
successful work emitted no per-scan spans. No lifecycle span happened to be stored
in this sampled run; lifecycle behavior retains its code-test evidence.
Every exported warning had severity number **13**, fixed body
`scan requires investigation`, and only string `outcome` plus numeric
`duration_seconds` attributes. Calibration/burst logs correlated to their stored
child spans. The unsampled probe retained valid trace/span IDs without a stored
span. Rejection diagnostics are instantaneous; their duration is not end-to-end
HTTP latency. No payload, raw error, URL, credential, or workload attribute exported.

### Cardinality and resource observations

Before calibration, SigNoz held **12 distinct stored metric names**, **14
service/name pairs**, and **26 application series** across both processes. After
the rejection counter first appeared, these became **13 / 15 / 27**, remaining
stable through the 1000-request burst and shutdown.

These counts are not interchangeable with OTLP instruments/data points. The active
scan histogram expands to **13 bucket series plus count, sum, min and max**:
**17 stored series for one histogram attribute set**. Projecting these families
back to the source gives **10 active per-service instrument/data-point sets**
before calibration and **11** after it (8/9 distinct source instrument names,
since the two runtime instruments appear in both services). This is a derivation
from stored families, **not direct capture of live OTLP requests**; registered but
unobserved instruments are absent from ingested counts.

Collector span metrics added **21 series**: `signoz_calls_total` (1),
`signoz_latency.bucket` (18), count (1), sum (1). The pre-burst and final combined
count was therefore **48 related stored series**, not 27. Collector dimensions
include service, operation, span kind/status, histogram boundary and collector
identity; those processors were unchanged.

Observed application dimension keys/values were:

- `endpoint`: `scanCP`, `generateSBOM`;
- `outcome`: `success`; `reason`: `none`, `invalid_request`;
- histogram `le`: the 12 configured boundaries plus `+Inf`;
- SDK/collector `__temporality__`: `Cumulative`, `Unspecified`.

These are application metric dimensions; resource and collector-generated dimensions
are accounted for separately. The burst did not exercise the 256-attribute-set
cardinality cap or a broad population of failure combinations.

Both test containers stayed ready with **zero restarts** after startup. Point
samples for main/scanner were **1m CPU / 1647 MiB** and **1m / 17 MiB** before the
burst; **259m / 1641 MiB** and **1m / 17 MiB** afterward; **554m / 1644 MiB** and
**1m / 16 MiB** before restoration. Organic scans and DB memory/cache activity were
present. These are snapshots, not peak usage, a sustained capacity limit, or an A/B
measurement of telemetry overhead.

## Bytes, checks and remaining gaps

The actual `signozmeter` connector uses **`metrics_flush_interval: 1h`** and only
service/environment/host dimensions, not the unique test version. Its schema
includes byte meters for spans, logs and metric data points. No attributable
kubevuln meter rows were available through the final query. **Live bytes by signal
and an hourly ingest/wire rate were not measured.** Neither compressed storage,
other fleet traffic, client request bytes nor local synthetic protobuf/gzip sizes
were substituted. The earlier local receiver measurements remain separate.

Fresh local checks passed: `go test ./...`, targeted race checks (including the
new rejection path), `go vet ./...`, `make lint`, formatting/diff checks, and both
binary builds for both architectures. Independent review approved the rejection
change. The earlier local Docker Grype-fixture limitation is recorded in the main
telemetry document; PR CI for the original implementation had passed all checks.

Unverified: live backend outage recovery and exporter queue drops, a representative
hourly/fleet byte budget, statistical sampler frequency, all scan modes and failure
classes, live full downstream HTTP/gRPC trace trees, and worst-case shutdown under
a saturated queue/backend outage. HTTP parent-to-diagnostic linkage was verified;
backend/scanner propagation retains code-test evidence. No collector or shared-library
source changes were made. This PR upgraded `github.com/kubescape/go-logger` from
v0.0.33 to v0.0.35. Permanent scanner credentials/discovery/resource
configuration and grace-period assessment remain deployment follow-ups.

## Final restoration

Restoration began at **11:06:02.237 UTC**, after observing an empty waiting queue.
SigNoz received final metric collections from **both** test processes at
**11:06:04.580 UTC**, before the next scheduled minute collection, including final
counts of 86 organic completions, 1002 rejections and 999 suppressed pairs. This
provides live evidence of shutdown metric export, not proof that every queued
record survives every shutdown failure mode.

The original image became ready after cold database warm-up at **11:09:25.784088 UTC**. A final independent comparison at
**11:10:11.585 UTC** confirmed **exact equality of the complete saved original
Deployment spec**, one ready replica, both original images, and removal of all
temporary environment/mount/annotation changes. At **11:12:05.755 UTC**, both
restored containers were ready with zero restarts and their actual image digests
matched the saved baseline. The watchdog and component
port-forward were stopped, and the temporary registry credential copy was removed.
No runtime captures, image binaries or credential copies were added to the repository. The unique test image tags
remain in the registry for reproducibility; they are not release tags.
Collector Deployment spec and both configuration maps remained equal. Their
normalized configuration-data SHA-256 was unchanged:
`02c4333eb22276a1627217e7c33f85094d16d9d99a206ab972f9c4d6b4e35753`.
No unrelated concurrent spec change was observed or overwritten. Controller-managed
revision/generation/status fields naturally changed during the rollouts.
