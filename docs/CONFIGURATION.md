# Kubevuln Configuration Guide

This document provides comprehensive documentation for configuring Kubevuln.

---

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Environment Variables](#environment-variables)
- [Configuration File Reference](#configuration-file-reference)
- [CVE Matching Mode](#cve-matching-mode)
- [Backend Services Configuration](#backend-services-configuration)
- [Credentials Configuration](#credentials-configuration)
- [Deploying the SBOM Scanner Sidecar](#deploying-the-sbom-scanner-sidecar)
- [Configuration Examples](#configuration-examples)
- [Configuration Precedence](#configuration-precedence)
- [Validation](#validation)

---

## Overview

Kubevuln uses a layered configuration system:

```
┌─────────────────────────────────────────┐
│           Environment Variables          │  ← Highest priority
├─────────────────────────────────────────┤
│         clusterData.json file           │
├─────────────────────────────────────────┤
│            Default Values               │  ← Lowest priority
└─────────────────────────────────────────┘
```

Configuration is loaded at startup from the directory specified by `CONFIG_DIR`.

---

## Configuration Methods

### Method 1: Configuration Directory (Recommended)

Create a directory with configuration files:

```bash
mkdir -p /etc/kubevuln/config

# Main configuration
cat > /etc/kubevuln/config/clusterData.json << 'EOF'
{
  "accountID": "my-account",
  "clusterName": "production"
}
EOF

# Backend services (optional)
cat > /etc/kubevuln/config/services.json << 'EOF'
{
  "version": "v2",
  "services": {
    "apiServer": "https://api.backend.com",
    "reportReceiver": "https://report.backend.com"
  }
}
EOF

# Start with config directory
CONFIG_DIR=/etc/kubevuln/config ./kubevuln
```

### Method 2: Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubevuln-config
  namespace: kubescape
data:
  clusterData.json: |
    {
      "accountID": "my-account",
      "clusterName": "production",
      "storage": true,
      "scanConcurrency": 4
    }
```

Mount in your deployment:

```yaml
volumes:
  - name: config
    configMap:
      name: kubevuln-config
volumeMounts:
  - name: config
    mountPath: /etc/config
```

---

## Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CONFIG_DIR` | Directory containing configuration files | `/etc/config` | `/app/config` |
| `OTEL_COLLECTOR_SVC` | OpenTelemetry collector endpoint | _(disabled)_ | `otel-collector:4317` |
| `RELEASE` | Version string for telemetry | _(empty)_ | `v1.0.0` |

### CONFIG_DIR

Specifies the directory where Kubevuln looks for configuration files.

```bash
export CONFIG_DIR=/path/to/config
./kubevuln
```

Expected files in this directory:
- `clusterData.json` (required) - Main configuration
- `services.json` (optional) - Backend service URLs
- `credentials` (optional) - Directory with credential files

### OTEL_COLLECTOR_SVC

Enables OpenTelemetry tracing. Set to your collector's address.

```bash
export OTEL_COLLECTOR_SVC=otel-collector:4317
./kubevuln
```

When enabled, Kubevuln will send traces for:
- HTTP request handling
- SBOM generation
- CVE scanning
- Database updates

### RELEASE

Version identifier included in telemetry data.

```bash
export RELEASE=v1.2.3
./kubevuln
```

---

## Configuration File Reference

### clusterData.json

The main configuration file. All options can be overridden via environment variables using UPPER_SNAKE_CASE (e.g., `scanTimeout` → `SCANTIMEOUT`).

#### Required Fields

| Option | Type | Description |
|--------|------|-------------|
| `accountID` | string | Account identifier for backend services |
| `clusterName` | string | Name of the Kubernetes cluster |

#### Scanning Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxImageSize` | int | `536870912` | Maximum image size to scan in bytes (default: 512 MB) |
| `maxSBOMSize` | int | `20971520` | Maximum SBOM size in bytes (default: 20 MB). Enforced after SBOM generation completes, not during it — Syft doesn't expose an incremental size hook, so an oversized SBOM is rejected only once it has already been built in memory. During generation, actual memory use is bounded by the memory limit of whichever container runs Syft, not by this value: the `sbom-scanner` sidecar container when `SBOM_SCANNER_SOCKET` is configured, or the main kubevuln container otherwise (in-process `SyftAdapter`). The scanner protocol carries this limit as a 32-bit value, so when the sidecar is in use a configured limit above `2147483647` (2 GiB) is clamped to that maximum and a warning is logged. The in-process adapter has no such ceiling. |
| `scanConcurrency` | int | `1` | Number of concurrent scans |
| `maxQueueDepth` | int | `0` | Maximum number of scans accepted but not yet finished (queued or running) that the HTTP controller will hold at once. `0` or a negative value means unbounded, matching the pre-existing behavior: `workerpool.Submit` never blocks, so without this a sustained burst of requests past `scanConcurrency` grows the backlog — and the registry credentials each queued job holds onto — without limit. Once set to a positive value and reached, new scan requests are rejected with `503` instead of being queued, so a caller handling that status can retry later rather than assuming the scan is in flight. This counts total pending scans (queued + running), which differs from the `kubevuln_worker_pool_queue_depth` metric (queued only, via the worker pool's own `WaitingQueueSize()`) — a scan can count against this limit while that gauge reads `0`. |
| `scanTimeout` | duration | `5m` | Timeout for SBOM generation. The scanner protocol carries this as whole seconds, so when the `sbom-scanner` sidecar is in use a sub-second value is rounded up to `1s` and any fractional part is rounded up to the next second. The in-process `SyftAdapter` applies the value exactly. |
| `scanEmbeddedSBOMs` | bool | `false` | Scan for embedded SBOMs in images |
| `scannerReadinessTimeout` | duration | `60s` | Maximum time to wait for the SBOM scanner sidecar to become ready at startup. A value of `0` or less does not mean "wait forever": it makes the readiness deadline expire immediately, causing startup to fall back to the built-in Syft scanner right away. |

#### Shutdown Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `shutdownTimeout` | duration | `20s` | Maximum time to wait for in-flight scans to finish when the process receives a shutdown signal; any not-yet-started, queued scans are abandoned immediately. This is added on top of the HTTP server's own fixed 5s shutdown window (hardcoded in `cmd/http/main.go`), not a replacement for it — budget `5s + shutdownTimeout` when sizing your pod's `terminationGracePeriodSeconds`. A value of `0` or less does not mean "wait forever": like `scannerReadinessTimeout`, it makes the deadline expire immediately, so the drain races the abandonment path from the start. |

#### Vulnerability Database Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listingURL` | string | `https://grype.anchore.io/databases` | Grype vulnerability database URL |
| `cveMatchingMode` | string | `adaptive` | CPE matching policy: `off` (Grype defaults everywhere), `on` (aggressive CPE matching everywhere), or `adaptive` (CPE matching everywhere except trusted-vendor images, which fall back to Grype defaults). See [CVE Matching Mode](#cve-matching-mode). |
| `trustedVendors` | []string | `["echo","chainguard","wolfi","minimos"]` | Distro identifiers (as recognised by Grype's distro detection) treated as trusted vendors in `adaptive` mode. Override to add/remove vendors without a release. Via `TRUSTEDVENDORS` env var, use a comma-separated list, e.g. `TRUSTEDVENDORS=echo,chainguard`. |
| `useDefaultMatchers` | bool | `false` | **Deprecated**, kept for backward compatibility. Maps to `cveMatchingMode`: `true` -> `off`, `false` -> `on`. An explicit `cveMatchingMode` always wins. |

#### Storage Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage` | bool | `false` | Enable Kubernetes storage backend (stores SBOMs/CVEs as CRDs) |
| `namespace` | string | `kubescape` | Kubernetes namespace for storage |
| `storeFilteredSbom` | bool | `false` | Store relevancy-filtered SBOMs |
| `riskAcceptance` | bool | `false` | Enable `SecurityException`/`ClusterSecurityException` CRD integration (exception matching, VEX suppression, suppression Events/metrics) — requires `storage: true` as well. See [security-exception-design.md](security-exception-design.md). If `storage` is enabled but this is left unset, matching CRDs are silently ignored: a warning is logged at startup, but no error or metric flags it, so double-check this is set before relying on `SecurityException`/`ClusterSecurityException` CRDs. |

#### Feature Flags

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keepLocal` | bool | `false` | Don't send reports to backend (local mode) |
| `nodeSbomGeneration` | bool | `false` | Enable node-level SBOM generation |
| `partialRelevancy` | bool | `false` | Enable partial relevancy matching |
| `vexGeneration` | bool | `false` | Generate VEX (Vulnerability Exploitability eXchange) documents. Requires `storage: true`. See [VEX.md](VEX.md) for what is produced, when, and how a status is chosen. |
| `proxyRegistryMap` | map[string]string | `{}` | Maps a registry hostname to an internal mirror for image pulls, e.g. `{"docker.io": "my-mirror.example.com"}`. Applied to every SBOM-generation path (in-process and sidecar). Config keys are parsed with a `::` delimiter specifically so hostnames containing `.` are treated as a single map key instead of being split into nested keys (see #359/#361) — no special escaping needed in `docker.io`-style keys. Via `PROXYREGISTRYMAP` env var, pass the whole map as a JSON object string, e.g. `PROXYREGISTRYMAP='{"docker.io":"my-mirror.example.com"}'` (single-quote in shells so the double quotes reach the process unescaped; malformed JSON now fails config loading with an error instead of silently disabling mirroring). |

### Complete Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["accountID", "clusterName"],
  "properties": {
    "accountID": {
      "type": "string",
      "description": "Account identifier"
    },
    "clusterName": {
      "type": "string",
      "description": "Cluster name"
    },
    "keepLocal": {
      "type": "boolean",
      "default": false
    },
    "listingURL": {
      "type": "string",
      "default": "https://grype.anchore.io/databases"
    },
    "maxImageSize": {
      "type": "integer",
      "default": 536870912
    },
    "maxQueueDepth": {
      "type": "integer",
      "default": 0
    },
    "maxSBOMSize": {
      "type": "integer",
      "default": 20971520
    },
    "namespace": {
      "type": "string",
      "default": "kubescape"
    },
    "nodeSbomGeneration": {
      "type": "boolean",
      "default": false
    },
    "partialRelevancy": {
      "type": "boolean",
      "default": false
    },
    "proxyRegistryMap": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "default": {}
    },
    "riskAcceptance": {
      "type": "boolean",
      "default": false
    },
    "scanConcurrency": {
      "type": "integer",
      "default": 1,
      "minimum": 1
    },
    "scanEmbeddedSBOMs": {
      "type": "boolean",
      "default": false
    },
    "scanTimeout": {
      "type": "string",
      "default": "5m",
      "pattern": "^([0-9]+(\\.[0-9]*)?(ns|us|µs|ms|s|m|h))+$"
    },
    "scannerReadinessTimeout": {
      "type": "string",
      "default": "60s",
      "pattern": "^([0-9]+(\\.[0-9]*)?(ns|us|µs|ms|s|m|h))+$"
    },
    "shutdownTimeout": {
      "type": "string",
      "default": "20s",
      "pattern": "^-?([0-9]+(\\.[0-9]*)?(ns|us|µs|ms|s|m|h))+$"
    },
    "storage": {
      "type": "boolean",
      "default": false
    },
    "storeFilteredSbom": {
      "type": "boolean",
      "default": false
    },
    "cveMatchingMode": {
      "type": "string",
      "enum": ["off", "on", "adaptive"],
      "default": "adaptive"
    },
    "trustedVendors": {
      "type": "array",
      "items": { "type": "string" },
      "default": ["echo", "chainguard", "wolfi", "minimos"]
    },
    "useDefaultMatchers": {
      "type": "boolean",
      "default": false
    },
    "vexGeneration": {
      "type": "boolean",
      "default": false
    }
  }
}
```

---

## CVE Matching Mode

Kubevuln uses Grype as its scanning engine. Grype connects packages to CVEs
through two mechanisms: ecosystem/feed-based matching and CPE name-fuzzing.
CPE matching avoids false negatives but, for images whose vendor maintains an
authoritative vulnerability feed already in the Grype DB, it only adds false
positives. `cveMatchingMode` controls this trade-off.

| Mode | Behavior |
|------|----------|
| `off` | Grype defaults everywhere (CPE matching disabled). Equivalent to the legacy `useDefaultMatchers: true`. |
| `on` | CPE matching enabled everywhere (most aggressive). Equivalent to the legacy `useDefaultMatchers: false`. |
| `adaptive` **(default)** | CPE matching enabled, except when the scanned image's distro is a trusted vendor, in which case Grype defaults apply for that scan. |

### Trusted vendors

In `adaptive` mode, the per-scan decision reuses Grype's own distro detection:
Syft parses the image's `/etc/os-release` into the SBOM, and Grype maps the
release ID to a distro type. When that type is in `trustedVendors`, CPE
matching is disabled for that scan and matching relies on the vendor's
authoritative feed. The default set is `echo` (Echo.ai), `chainguard` and
`wolfi` (Chainguard), and `minimos` (Minimus).

### Backward compatibility

The legacy `useDefaultMatchers` boolean is still honored. When
`cveMatchingMode` is not set explicitly, the boolean is mapped to a mode
(`true` -> `off`, `false` -> `on`). An explicit `cveMatchingMode` always wins.
If neither is set, the mode defaults to `adaptive`.

### Observability

When `adaptive` mode downgrades a scan to a trusted vendor's feed, the CVE
manifest is annotated with `kubescape.io/cve-matching-mode` and
`kubescape.io/vendor-trusted-match`, so the backend/UI can explain why two
similar images may show different vulnerability counts.

---

## Backend Services Configuration

Kubevuln resolves backend service URLs in this order:
1. `services.json` (if present)
2. `API_URL` service discovery
3. static `clusterData.json` values (`backendOpenAPI` + `eventReceiverRestURL`)

### services.json

Configures URLs for Kubescape backend services.

```json
{
  "version": "v2",
  "services": {
    "apiServer": "https://api.example.com",
    "reportReceiver": "https://report.example.com"
  }
}
```

| Field | Description |
|-------|-------------|
| `version` | Schema version (use `v2`) |
| `services.apiServer` | API server URL for fetching data |
| `services.reportReceiver` | Report receiver URL for sending scan results |

---

## Credentials Configuration

### Backend Credentials

Place credentials in `/etc/credentials/`:

```
/etc/credentials/
├── account    # Account ID
└── accessKey  # Access key for backend authentication
```

### Registry Credentials

Registry credentials are passed per-request in the API payload:

```json
{
  "credentialslist": [
    {
      "username": "user",
      "password": "password-or-token",
      "serveraddress": "registry.example.com"
    }
  ]
}
```

For Kubernetes, use imagePullSecrets which Kubevuln will automatically use.

---

## Deploying the SBOM Scanner Sidecar

Setting `SBOM_SCANNER_SOCKET` moves SBOM generation out of the kubevuln process and into a
second container. See [SBOM Generation Modes](ARCHITECTURE.md#sbom-generation-modes) for why
the split exists; this section is what a deployment has to get right for it to work.

Both binaries ship in the same image. `build/Dockerfile` builds `kubevuln` and `sbom-scanner`
into `/usr/bin`, and `ENTRYPOINT` is `kubevuln`, so the sidecar container runs the same image
with its command overridden to `sbom-scanner`. There is no separate image to pull or tag.

### The four things a deployment has to line up

**1. The socket path, on both sides.** The sidecar listens on `SOCKET_PATH` (default
`/sbom-comm/scanner.sock`); kubevuln dials `SBOM_SCANNER_SOCKET`. These are separate variables
and nothing validates that they agree. They must name the same path on a volume both
containers mount, since a Unix domain socket is a filesystem object.

If they disagree, kubevuln's readiness check fails and it falls back to in-process Syft. The
deployment keeps working and nothing says the sidecar is idle, which is why the verification
step below is worth doing.

**2. A shared `/tmp`, for correctness rather than convenience.** Both processes write
stereoscope temp directories under `os.TempDir()`, and both run a periodic sweep that removes
stale ones. The sweep coordinates across the two processes with a `flock` lease on a file in
that same directory (`.kubevuln-active-scan.lock`).

That coordination only holds if both containers mount the *same* volume at `/tmp`. Give them
separate `emptyDir`s and each process gets its own lock file, so neither sees the other's
lease, and one container's sweep can delete a directory the other is still cataloguing from.
The failure is a scan that fails partway through with a missing-file error, at whatever
interval the sweeps happen to collide.

The Helm chart mounts a single `tmp-dir` volume on both containers. A hand-written manifest
has to do the same.

**3. Distinct metrics ports.** Containers in a Pod share one network namespace. kubevuln binds
`:8080` and serves `/metrics` there; the sidecar defaults to `:8081` via `METRICS_ADDR`
precisely so the two do not collide. Pointing both at the same port means the sidecar fails to
bind and its `component="sidecar"` series, including
`kubevuln_temp_dir_sweep_removed_total`, are never served, while kubevuln carries on
unaffected.

**4. A memory limit that means something.** Containing OOM is the reason for the split, so the
sidecar container wants a memory limit set. `SCANNER_MEMORY_LIMIT` should be given the same
value: it is read at startup and recorded on an SBOM the scanner reports as too large, so a
result can be read back against the limit that produced it.

### Environment variables

| Variable | Container | Default | Description |
|----------|-----------|---------|-------------|
| `SBOM_SCANNER_SOCKET` | kubevuln | _(unset)_ | Socket to dial. Unset means in-process Syft. |
| `SOCKET_PATH` | sbom-scanner | `/sbom-comm/scanner.sock` | Socket to listen on. Must match the above. |
| `METRICS_ADDR` | sbom-scanner | `:8081` | Prometheus listen address. Must not collide with kubevuln's `:8080`. |
| `SCANNER_MEMORY_LIMIT` | kubevuln | _(unset)_ | Recorded on an SBOM reported as too large for the scanner. |

`scannerReadinessTimeout` (listed in the [Complete Schema](#complete-schema)) bounds how
long kubevuln waits for the sidecar at startup before falling back.

### Verifying which mode is actually running

Startup is deliberately fail-soft: if the sidecar never becomes ready within
`scannerReadinessTimeout`, kubevuln logs the failure and continues with the in-process
adapter rather than refusing to start. A deployment can therefore be running in a different
mode than its configuration suggests.

`/v1/diagnostics` reports which:

```bash
curl -s http://localhost:8080/v1/diagnostics | jq .scanMode
# "sidecar"     SBOMs are generated by the sbom-scanner container
# "in-process"  Syft is running inside kubevuln
```

Seeing `in-process` with `SBOM_SCANNER_SOCKET` set means the readiness check did not pass.
The startup log carries the reason:

```
SBOM scanner sidecar not ready after readiness timeout, falling back to in-process Syft
```

Usual causes, in the order worth checking: the two socket paths do not agree, the volume
carrying the socket is not mounted on both containers, or the sidecar container is not running
at all.

### What the sidecar does not change

Concurrency behaves differently between the two modes and this is deliberate rather than an
oversight. The in-process adapter serialises image pulls behind a mutex so concurrent scans
cannot exhaust local disk. The sidecar does not, and bounds in-flight work by the caller's
`scanConcurrency` instead. Raising `scanConcurrency` therefore has more effect on disk usage
in sidecar mode than in-process.

Everything else is unchanged: the same `maxImageSize` and `maxSBOMSize` limits apply, the same
`scanTimeout` bounds generation, and results are stored and reported identically. The scan
service holds one interface and does not know which implementation it has.

## Configuration Examples

### Local Development

Minimal configuration for local testing:

```json
{
  "accountID": "local-dev",
  "clusterName": "dev-cluster",
  "keepLocal": true,
  "scanTimeout": "10m"
}
```

### Small Cluster

For clusters with < 100 pods:

```json
{
  "accountID": "your-account",
  "clusterName": "small-cluster",
  "namespace": "kubescape",
  "storage": true,
  "scanConcurrency": 2,
  "scanTimeout": "5m",
  "maxImageSize": 536870912,
  "maxSBOMSize": 20971520
}
```

### Medium Cluster

For clusters with 100-500 pods:

```json
{
  "accountID": "your-account",
  "clusterName": "medium-cluster",
  "namespace": "kubescape",
  "storage": true,
  "scanConcurrency": 4,
  "scanTimeout": "10m",
  "maxImageSize": 1073741824,
  "maxSBOMSize": 41943040,
  "vexGeneration": true
}
```

### Large Cluster

For clusters with > 500 pods:

```json
{
  "accountID": "your-account",
  "clusterName": "large-cluster",
  "namespace": "kubescape",
  "storage": true,
  "scanConcurrency": 8,
  "scanTimeout": "15m",
  "maxImageSize": 2147483648,
  "maxSBOMSize": 52428800,
  "cveMatchingMode": "off",
  "vexGeneration": true,
  "partialRelevancy": true
}
```

### Air-Gapped Environment

For environments without internet access:

```json
{
  "accountID": "airgap-account",
  "clusterName": "airgap-cluster",
  "keepLocal": true,
  "storage": true,
  "listingURL": "http://internal-grype-db-mirror:8080/databases",
  "scanConcurrency": 2,
  "scanTimeout": "10m"
}
```

### CI/CD Pipeline

For scanning in CI/CD:

```json
{
  "accountID": "ci-account",
  "clusterName": "ci-runner",
  "keepLocal": true,
  "scanConcurrency": 1,
  "scanTimeout": "5m",
  "maxImageSize": 1073741824
}
```

---

## Configuration Precedence

Values are resolved in this order (highest to lowest priority):

1. **Environment Variables** - `SCANCONCURRENCY=4`
2. **Configuration File** - `clusterData.json`
3. **Default Values** - Built into the application

Example:

```bash
# Default is 1
# Config file sets 4
# Environment variable sets 8

# Result: 8 (env var wins)
SCANCONCURRENCY=8 CONFIG_DIR=/config ./kubevuln
```

---

## Validation

### Startup Validation

Kubevuln validates configuration at startup. Invalid configuration will prevent the service from starting.

Required fields:
- `accountID` (when `keepLocal` is `false`)
- `clusterName`

### Runtime Validation

Some configuration is validated at runtime:
- `maxImageSize` - Images larger than this are skipped
- `maxSBOMSize` - SBOMs larger than this are marked as "too large"
- `scanTimeout` - Scans exceeding this duration are terminated

### Common Validation Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `load config error` | Missing or invalid `clusterData.json` | Check file exists and is valid JSON |
| `missing required field` | Required field not set | Add `accountID` and `clusterName` |
| `invalid duration` | Invalid `scanTimeout` format | Use format like `5m`, `1h`, `300s` |

---

## Tuning Guidelines

### Memory Usage

| Setting | Impact |
|---------|--------|
| `maxImageSize` | Higher = more memory for image download |
| `maxSBOMSize` | Higher = more memory for SBOM storage |
| `scanConcurrency` | Higher = more parallel memory usage |

**Recommendation:** Set memory limits to at least `2 * maxImageSize * scanConcurrency`

### CPU Usage

| Setting | Impact |
|---------|--------|
| `scanConcurrency` | Higher = more CPU usage |
| `cveMatchingMode` | `off`/`adaptive` = less CPU than `on` (fewer CPE matches) |

### Disk Usage

| Setting | Impact |
|---------|--------|
| `storage` | `true` = stores SBOMs/CVEs in Kubernetes |
| `storeFilteredSbom` | `true` = additional storage for filtered SBOMs |

### Network Usage

| Setting | Impact |
|---------|--------|
| `maxImageSize` | Limits download size |
| `listingURL` | DB updates (daily, ~50MB) |
| `keepLocal` | `true` = no backend communication |

---

## See Also

- [README.md](../README.md) - Main documentation
- [API.md](API.md) - API reference
- [Kubescape Helm Chart](https://github.com/kubescape/helm-charts) - Production deployment