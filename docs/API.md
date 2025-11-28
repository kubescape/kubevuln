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

## Scan Endpoints

All scan endpoints accept a JSON payload and return immediately with a `200 OK` status. The actual scanning is performed asynchronously in a worker pool.

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
| `400 Bad Request` | Invalid request payload |
| `500 Internal Server Error` | Validation failed |

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
| `400 Bad Request` | Invalid request payload |
| `500 Internal Server Error` | Validation failed |

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
| `400 Bad Request` | Invalid request payload |
| `500 Internal Server Error` | Validation failed |

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
| `400 Bad Request` | Invalid request payload |
| `500 Internal Server Error` | Validation failed |

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
| `400` | Bad Request | Invalid JSON or missing required fields |
| `500` | Internal Server Error | Validation failed or internal error |
| `503` | Service Unavailable | Service not ready (vulnerability DB not loaded) |

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
  "status": 500,
  "title": "Internal Server Error",
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

---

## Rate Limiting

Kubevuln implements internal concurrency control via a worker pool. The number of concurrent scans is controlled by the `scanConcurrency` configuration option.

When the worker queue is full, requests are still accepted but will be queued for processing.

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