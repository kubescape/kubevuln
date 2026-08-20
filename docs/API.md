# Kubevuln API Reference

This document provides detailed documentation for the Kubevuln REST API.

## Overview

Kubevuln exposes a REST API on port **8080** for vulnerability scanning operations. The API follows REST conventions and returns responses in the [RFC 7807 Problem Details](https://tools.ietf.org/html/rfc7807) format.

---

## Table of Contents

- [Base URL](#base-url)
- [Authentication](#authentication)
- [Health Endpoints](#health-endpoints)
  - [Liveness Probe](#liveness-probe)
  - [Readiness Probe](#readiness-probe)
  - [Metrics](#metrics)
  - [Diagnostics](#diagnostics)
- [Scan Endpoints](#scan-endpoints)
  - [Generate SBOM](#generate-sbom)
  - [Scan Image for CVEs](#scan-image-for-cves)
  - [Scan Registry Image](#scan-registry-image)
  - [Application Profile Scan](#application-profile-scan)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Examples](#examples)

---

## Base URL

```
http://<kubevuln-host>:8080
```

In-cluster, this is typically:
```
http://kubevuln.kubescape.svc.cluster.local:8080
```

---

## Authentication

Kubevuln does not implement authentication directly. Access control should be managed at the network level (e.g., Kubernetes NetworkPolicies, service mesh).

For scanning private container registries, credentials are passed in the request payload.

---

## Health Endpoints

### Liveness Probe

Check if the server is running.

```
GET /v1/liveness
```

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Server is running |

#### Example

```bash
curl http://localhost:8080/v1/liveness
```

```json
{
  "status": 200,
  "title": "OK"
}
```

---

### Readiness Probe

Check if the server is ready to process requests (vulnerability database is loaded).

```
GET /v1/readiness
```

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Server is ready |
| `503 Service Unavailable` | Vulnerability database not loaded |

#### Example

```bash
curl http://localhost:8080/v1/readiness
```

Success response:
```json
{
  "status": 200,
  "title": "OK"
}
```

Not ready response:
```json
{
  "status": 503,
  "title": "Service Unavailable"
}
```

---

### Metrics

Prometheus exposition-format metrics for the HTTP controller and its worker pool. Served
on the same port as the health endpoints, with no auth or network guard -- fine for how
kubevuln is deployed today (the Service isn't public and the metrics carry no
tenant/image identifiers), but scraping it in a cluster requires a chart-side change
(`prometheus.io/scrape` annotations or a `ServiceMonitor`) since the endpoint shipping
here doesn't by itself get collected.

```
GET /metrics
```

#### Instruments

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `kubevuln_scans_completed_total` | counter | `endpoint`, `outcome` (`success`/`partial`/`error`), `reason` | Scans completed by the HTTP controller's worker pool |
| `kubevuln_scan_duration_seconds` | histogram | `endpoint`, `outcome`, `reason` | Duration of a scan job, measured from when it starts running (not from when it was queued) |
| `kubevuln_scan_rejections_total` | counter | `endpoint`, `reason` (`too_many_requests`/`invalid_request`) | Requests rejected at validation time, before being queued |
| `kubevuln_worker_pool_queue_depth` | gauge | - | Number of scan jobs currently waiting in the worker pool |
| `kubevuln_exceptions_degraded_total` | counter | - | Total number of times CVE exception fetching degraded (partially failed) during a scan |
| `kubevuln_exceptions_matched_total` | counter | `sourceKind` (`SecurityException`/`ClusterSecurityException`) | Total number of CVE findings suppressed by a SecurityException/ClusterSecurityException |
| `kubevuln_exceptions_expired_total` | counter | `sourceKind` | Total number of SecurityException/ClusterSecurityException CRDs skipped because their `expiresAt` has passed |
| `kubevuln_exceptions_active` | gauge | - | Number of CVE exception policies (cloud + CRD-based) in force for the most recently evaluated scan |
| `kubevuln_scan_fallbacks_total` | counter | `component` (`in_process`/`sidecar`), `category` (`registry_auth`/`platform`/`size_classification`), `strategy` (`anonymous`/`ecr`/`gcp_adc`/`image_too_large`/`incomplete`/`platform_mismatch`/`sbom_too_large`), `outcome` (`classified`/`failed`/`succeeded`) | Fallbacks taken while resolving or classifying a scan, such as retrying a 401 with cloud credentials or falling back to anonymous access |
| `kubevuln_scan_source_resolution_total` | counter | `component`, `outcome` (`first_pass_success`/`fallback_assisted_success`/`fallback_failed`/`first_pass_failure`) | Whether pulling the image succeeded outright or only after a fallback, which is what distinguishes a healthy registry from one that works only by retry |
| `kubevuln_registry_auth_cache_total` | counter | `strategy` (`ecr`/`gcp_adc`), `result` (`hit`/`miss`/`coalesced`) | Registry auth credential lookups, by what each one cost: `hit` served from cache, `coalesced` served by another concurrent lookup's in-flight fetch, `miss` reached the cloud provider. `miss` is therefore the number of upstream credential fetches |
| `kubevuln_singleflight_hits_total` | counter | `target` (`sbom_generation`) | Scan requests that arrived while the same work was already in flight and were served by it, so they did not generate an SBOM of their own. Counts the requests spared the work, not the one doing it |
| `kubevuln_retry_attempts_total` | counter | `operation` (`source_resolution`/`sbom_generation`), `outcome` (`attempt`/`success`/`exhausted`) | Retry attempts executed during transient error backoff, distinguishing individual attempts, successes after retry, and exhausted retries |

`reason` is `"none"` for a `success`/`partial` outcome, and otherwise one of the bounded
`scanfailure.Reason*` constants from [`armoapi-go/scanfailure`](https://github.com/armosec/armoapi-go)
-- the same classification already sent to the backend via `ReportScanFailure` (see
[scan-failure-reporting.md](scan-failure-reporting.md)) -- falling back to `"unexpected_error"`
for an `error` outcome that carries no specific classification. This lets an operator watching
only `/metrics` distinguish, for example, a registry auth failure from an oversized image
without needing access to the backend's failure-report stream or pod logs.

#### Example

```bash
curl http://localhost:8080/metrics
```

---

### Diagnostics

Reports the scanner configuration actually in effect, which is not always the configuration
that was requested: if `SBOM_SCANNER_SOCKET` is set but the sidecar never becomes ready
within `scannerReadinessTimeout`, kubevuln logs the failure and falls back to the in-process
Syft adapter. `scanMode` is how you tell which one is running.

**Endpoint:** `GET /v1/diagnostics`

**Response:** `200 OK`

```json
{
  "scanMode": "sidecar",
  "sbomCreatorVersion": "v1.42.3",
  "cveScannerVersion": "v0.104.1-matching-adaptive",
  "cveDBVersion": "5e8b0e2c9f",
  "scanTimeout": "5m0s",
  "scannerReadinessTimeout": "1m0s",
  "storageEnabled": true,
  "riskAcceptanceEnabled": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `scanMode` | string | `sidecar` when SBOMs are generated by the `sbom-scanner` container, `in-process` when Syft runs inside kubevuln |
| `sbomCreatorVersion` | string | Syft version in use |
| `cveScannerVersion` | string | Grype version, suffixed with the active `cveMatchingMode` |
| `cveDBVersion` | string | Checksum of the loaded Grype vulnerability database; empty until the first load completes |
| `scanTimeout` | duration | Effective `scanTimeout` |
| `scannerReadinessTimeout` | duration | Effective `scannerReadinessTimeout` |
| `storageEnabled` | bool | Whether SBOMs and CVE manifests are persisted as CRDs |
| `riskAcceptanceEnabled` | bool | Whether SecurityException / ClusterSecurityException CRDs are applied |

Always returns `200`. When the controller was built without a diagnostics provider the
struct's zero value is returned, so an all-empty body means "not wired up" rather than
"nothing configured".

```bash
curl -s http://localhost:8080/v1/diagnostics | jq
```

---

## Scan Endpoints

All scan endpoints accept a JSON payload and return immediately with a `200 OK` status. The actual scanning is performed asynchronously in a worker pool.

### Get Scan Status

Look up the current lifecycle state for a previously submitted `jobID`.

```http
GET /v1/scanStatus/:jobID
```

#### Response Body

| Field | Type | Description |
|-------|------|-------------|
| `jobID` | string | Submitted job identifier |
| `endpoint` | string | Async scan endpoint handling this job |
| `state` | string | One of `queued`, `running`, `succeeded`, `failed`, or `abandoned` |
| `phase` | string | Current service phase. Reported values include `queued`, `running`, `relevancy_lookup`, `cve_lookup`, `sbom_generation`, `sbom_storage`, `cve_matching`, `result_storage`, `result_upload`, `completed`, and `abandoned` |
| `reason` | string | Machine readable terminal reason for `failed` or `abandoned` jobs |
| `acceptedAt` | string | RFC3339 timestamp when the request was accepted |
| `startedAt` | string | RFC3339 timestamp when execution began. Omitted while the job is still queued |
| `finishedAt` | string | RFC3339 timestamp when the job reached a terminal state. Omitted until the job succeeds, fails, or is abandoned |
| `updatedAt` | string | RFC3339 timestamp of the latest lifecycle transition |

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Job status found |
| `404 Not Found` | Unknown `jobID` |

#### Example

```bash
curl http://localhost:8080/v1/scanStatus/sbom-gen-001
```

```json
{
  "jobID": "sbom-gen-001",
  "endpoint": "generateSBOM",
  "state": "running",
  "phase": "sbom_generation",
  "acceptedAt": "2026-08-12T12:00:00Z",
  "startedAt": "2026-08-12T12:00:01Z",
  "updatedAt": "2026-08-12T12:00:01Z"
}
```

### Generate SBOM

Generate a Software Bill of Materials (SBOM) for a container image.

```
POST /v1/sbomCreation
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `imageTag` | string | Yes | Full image reference (e.g., `nginx:1.24`) |
| `imageHash` | string | No | Image digest (e.g., `sha256:abc123...`) |
| `wlid` | string | No | Workload ID |
| `jobID` | string | No | Unique job identifier |
| `containerName` | string | No | Container name |
| `parentJobID` | string | No | Parent job ID for tracking |
| `credentialslist` | array | No | Registry credentials |
| `args` | object | No | Additional arguments |
| `instanceID` | string | No | Instance identifier |

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Request accepted, SBOM generation started |
| `400 Bad Request` | Invalid request payload or validation failed |
| `429 Too Many Requests` | Registry rate limit hit on a previous pull for this image |
| `503 Service Unavailable` | Scan admission queue is full (`maxQueueDepth` reached); retry later. Unrelated to `/v1/readiness` |

#### Example

```bash
curl -X POST http://localhost:8080/v1/sbomCreation \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "nginx:1.24",
    "imageHash": "sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0",
    "jobID": "sbom-gen-001"
  }'
```

```json
{
  "status": 200,
  "title": "OK",
  "detail": "ImageHash=nginx@sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0"
}
```

---

### Scan Image for CVEs

Scan a container image for known vulnerabilities.

```
POST /v1/scanImage
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `imageTag` | string | Yes | Full image reference |
| `imageHash` | string | Yes | Image digest |
| `wlid` | string | Yes | Workload ID |
| `jobID` | string | No | Unique job identifier |
| `containerName` | string | No | Container name |
| `parentJobID` | string | No | Parent job ID |
| `credentialslist` | array | No | Registry credentials |
| `args` | object | No | Additional arguments |
| `instanceID` | string | No | Instance identifier |
| `lastAction` | int | No | Last action indicator |

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Request accepted, CVE scan started |
| `400 Bad Request` | Invalid request payload or validation failed |
| `429 Too Many Requests` | Registry rate limit hit on a previous pull for this image |
| `503 Service Unavailable` | Scan admission queue is full (`maxQueueDepth` reached); retry later. Unrelated to `/v1/readiness` |

#### Example

```bash
curl -X POST http://localhost:8080/v1/scanImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "nginx:1.24",
    "imageHash": "sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0",
    "wlid": "wlid://cluster-prod/namespace-default/deployment-nginx",
    "jobID": "cve-scan-001",
    "containerName": "nginx"
  }'
```

```json
{
  "status": 200,
  "title": "OK",
  "detail": "Wlid=wlid://cluster-prod/namespace-default/deployment-nginx, ImageHash=nginx@sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0"
}
```

---

### Scan Registry Image

Scan an image directly from a container registry (without workload context).

```
POST /v1/scanRegistryImage
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `imageTag` | string | Yes | Full image reference |
| `jobID` | string | No | Unique job identifier |
| `parentJobID` | string | No | Parent job ID |
| `credentialslist` | array | No | Registry credentials |
| `args` | object | No | Additional arguments |

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Request accepted, registry scan started |
| `400 Bad Request` | Invalid request payload or validation failed |
| `429 Too Many Requests` | Registry rate limit hit on a previous pull for this image |
| `503 Service Unavailable` | Scan admission queue is full (`maxQueueDepth` reached); retry later. Unrelated to `/v1/readiness` |

#### Example

```bash
curl -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "ghcr.io/kubescape/kubevuln:latest",
    "jobID": "registry-scan-001",
    "credentialslist": [
      {
        "username": "token",
        "password": "ghp_xxxxxxxxxxxx",
        "serveraddress": "ghcr.io"
      }
    ]
  }'
```

```json
{
  "status": 200,
  "title": "OK",
  "detail": "ImageTag=ghcr.io/kubescape/kubevuln:latest"
}
```

---

### Application Profile Scan

Scan based on a container's application profile for relevancy-filtered vulnerabilities.

```
POST /v1/applicationProfileScan
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wlid` | string | Yes | Workload ID |
| `args.name` | string | Yes | Profile name |
| `args.namespace` | string | Yes | Profile namespace |
| `jobID` | string | No | Unique job identifier |
| `parentJobID` | string | No | Parent job ID |
| `credentialslist` | array | No | Registry credentials |

#### Response

| Status | Description |
|--------|-------------|
| `200 OK` | Request accepted, profile scan started |
| `400 Bad Request` | Invalid request payload or validation failed |
| `503 Service Unavailable` | Scan admission queue is full (`maxQueueDepth` reached); retry later. Unrelated to `/v1/readiness` |

#### Example

```bash
curl -X POST http://localhost:8080/v1/applicationProfileScan \
  -H "Content-Type: application/json" \
  -d '{
    "wlid": "wlid://cluster-prod/namespace-default/deployment-nginx",
    "jobID": "profile-scan-001",
    "args": {
      "name": "nginx-profile",
      "namespace": "default"
    }
  }'
```

```json
{
  "status": 200,
  "title": "OK",
  "detail": "Wlid=wlid://cluster-prod/namespace-default/deployment-nginx, Name=nginx-profile, Namespace=default"
}
```

---

## Data Models

### WebsocketScanCommand

The main request payload for scan operations.

```json
{
  "imageTag": "string",
  "imageHash": "string",
  "wlid": "string",
  "jobID": "string",
  "containerName": "string",
  "parentJobID": "string",
  "lastAction": 0,
  "instanceID": "string",
  "credentialslist": [
    {
      "username": "string",
      "password": "string",
      "serveraddress": "string",
      "identitytoken": "string"
    }
  ],
  "args": {
    "key": "value"
  },
  "session": {
    "jobIDs": ["string"]
  }
}
```

### RegistryCredentials

Credentials for accessing private container registries.

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Registry username |
| `password` | string | Registry password or token |
| `serveraddress` | string | Registry server address |
| `identitytoken` | string | Identity token (alternative to password) |

### Problem Details Response

All responses follow RFC 7807.

```json
{
  "status": 200,
  "title": "OK",
  "detail": "Additional information about the response"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | int | HTTP status code |
| `title` | string | Short, human-readable summary |
| `detail` | string | Detailed explanation (optional) |

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | When |
|------|---------|------|
| `200` | OK | Request accepted |
| `400` | Bad Request | Invalid JSON, missing required fields, or validation failed |
| `429` | Too Many Requests | Registry rate limit hit on a previous pull for this image |
| `500` | Internal Server Error | Internal error |
| `503` | Service Unavailable | Two distinct causes, unrelated to each other: `/v1/readiness` reports it when the vulnerability DB isn't loaded, and a scan endpoint reports it when the admission queue is full (`maxQueueDepth` reached) |

### Common Errors

#### Invalid JSON

```json
{
  "status": 400,
  "title": "Bad Request"
}
```

#### Validation Error

```json
{
  "status": 400,
  "title": "Bad Request",
  "detail": "ImageHash=..."
}
```

---

## Examples

### Complete Scan Workflow

1. **Check service readiness:**

```bash
curl http://localhost:8080/v1/readiness
```

2. **Generate SBOM:**

```bash
curl -X POST http://localhost:8080/v1/sbomCreation \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "nginx:1.24",
    "imageHash": "sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0",
    "jobID": "workflow-sbom-001"
  }'
```

3. **Scan for CVEs:**

```bash
curl -X POST http://localhost:8080/v1/scanImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "nginx:1.24",
    "imageHash": "sha256:0463a96ac74b84a8a1b23c1810d89d03f0eb2a3b5a1c41fb5d4e1da4f5c9c7c0",
    "wlid": "wlid://cluster-prod/namespace-default/deployment-nginx",
    "jobID": "workflow-cve-001"
  }'
```

### Scanning Private Registry Images

```bash
curl -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "private.registry.com/myapp:v1.0.0",
    "jobID": "private-scan-001",
    "credentialslist": [
      {
        "username": "myuser",
        "password": "mypassword",
        "serveraddress": "private.registry.com"
      }
    ]
  }'
```

### Scanning with HTTP Registry (Insecure)

For development registries using HTTP:

```bash
curl -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "localhost:5000/myapp:latest",
    "jobID": "insecure-scan-001",
    "args": {
      "useHTTP": true,
      "skipTLSVerify": true
    }
  }'
```

### Requesting a Specific Image Platform

For multi-arch images, request a specific OS/architecture (OCI format `os/arch[/variant]`, or a
bare arch such as `arm64`) via the `platform` arg. An operator can populate this from the scanned
Pod's node architecture; left unset, kubevuln resolves whatever platform the image manifest
provides instead of forcing the host's own architecture:

```bash
curl -X POST http://localhost:8080/v1/sbomCreation \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "myapp:latest",
    "jobID": "multi-arch-scan-001",
    "args": {
      "platform": "linux/arm64"
    }
  }'
```

The platform actually resolved (which may differ from the request if none was given) is recorded
on the resulting SBOM's `kubescape.io/resolved-platform` annotation. Requesting a platform absent
from the image's manifest fails the scan with a distinguishable "platform not found" reason
instead of a generic error.

---

## Rate Limiting

Kubevuln implements internal concurrency control via a worker pool. The number of concurrent scans is controlled by the `scanConcurrency` configuration option.

Whether an accepted-but-unfinished scan past that concurrency is queued or rejected depends on `maxQueueDepth` (see [CONFIGURATION.md](CONFIGURATION.md#scanning-options)):

- **Unset, or `0`/negative (the default):** unbounded. Every request that passes validation is accepted and queued for processing, however large the backlog grows.
- **A positive value:** bounded. Once that many scans are accepted but not yet finished (queued or running), each of the four scan endpoints (`sbomCreation`, `scanImage`, `scanRegistryImage`, `applicationProfileScan`) rejects further requests with `503 Service Unavailable` instead of queuing them — see each endpoint's Response table above. Callers should treat this as a signal to retry later, not as an error with the request itself.

---

## OpenTelemetry Integration

When `OTEL_COLLECTOR_SVC` is set, all API endpoints are instrumented with OpenTelemetry tracing.

Traces include:
- Request handling duration
- SBOM generation time
- CVE scanning time
- Image download time

---

## See Also

- [README.md](../README.md) - Main documentation
- [CONFIGURATION.md](CONFIGURATION.md) - Detailed configuration guide
- [Kubescape Documentation](https://kubescape.io/docs/)
