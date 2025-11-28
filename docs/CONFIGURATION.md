# Kubevuln Configuration Guide

This document provides comprehensive documentation for configuring Kubevuln.

---

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Environment Variables](#environment-variables)
- [Configuration File Reference](#configuration-file-reference)
- [Backend Services Configuration](#backend-services-configuration)
- [Credentials Configuration](#credentials-configuration)
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
| `maxSBOMSize` | int | `20971520` | Maximum SBOM size in bytes (default: 20 MB) |
| `scanConcurrency` | int | `1` | Number of concurrent scans |
| `scanTimeout` | duration | `5m` | Timeout for SBOM generation |
| `scanEmbeddedSBOMs` | bool | `false` | Scan for embedded SBOMs in images |

#### Vulnerability Database Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listingURL` | string | `https://grype.anchore.io/databases` | Grype vulnerability database URL |
| `useDefaultMatchers` | bool | `false` | Use Grype's default matchers (less aggressive CPE matching) |

#### Storage Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage` | bool | `false` | Enable Kubernetes storage backend (stores SBOMs/CVEs as CRDs) |
| `namespace` | string | `kubescape` | Kubernetes namespace for storage |
| `storeFilteredSbom` | bool | `false` | Store relevancy-filtered SBOMs |

#### Feature Flags

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keepLocal` | bool | `false` | Don't send reports to backend (local mode) |
| `nodeSbomGeneration` | bool | `false` | Enable node-level SBOM generation |
| `partialRelevancy` | bool | `false` | Enable partial relevancy matching |
| `vexGeneration` | bool | `false` | Generate VEX (Vulnerability Exploitability eXchange) documents |

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
      "pattern": "^[0-9]+(s|m|h)$"
    },
    "storage": {
      "type": "boolean",
      "default": false
    },
    "storeFilteredSbom": {
      "type": "boolean",
      "default": false
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

## Backend Services Configuration

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
  "useDefaultMatchers": true,
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
| `useDefaultMatchers` | `true` = less CPU (fewer matches) |

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