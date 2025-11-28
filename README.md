# Kubevuln

[![CNCF Status](https://img.shields.io/badge/CNCF-Incubating-blue.svg)](https://www.cncf.io/projects/kubescape/)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/kubevuln/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/kubevuln)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln?ref=badge_shield&issueType=license)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kubescape/kubevuln)](https://github.com/kubescape/kubevuln/blob/main/go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/kubescape/kubevuln)](https://goreportcard.com/report/github.com/kubescape/kubevuln)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Kubevuln** is an in-cluster vulnerability scanner for Kubernetes, part of the [Kubescape](https://github.com/kubescape/kubescape) security platform. It automatically scans container images for known vulnerabilities (CVEs) using industry-standard tools.

---

## Table of Contents

- [Why Kubevuln?](#why-kubevuln)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Why Kubevuln?

| Challenge | How Kubevuln Helps |
|-----------|-------------------|
| **Runtime vulnerability detection** | Scans images as they're deployed to your cluster |
| **SBOM generation** | Creates Software Bill of Materials for compliance and auditing |
| **Integration with Kubescape** | Seamlessly works with the broader Kubescape security platform |
| **Relevancy filtering** | Identifies which vulnerabilities are actually loaded in running containers |
| **VEX support** | Generates Vulnerability Exploitability eXchange documents |

---

## Features

- 🔍 **Container Image Scanning** - Detect CVEs in container images using [Grype](https://github.com/anchore/grype)
- 📦 **SBOM Generation** - Create SBOMs using [Syft](https://github.com/anchore/syft)
- 🎯 **Relevancy Analysis** - Filter vulnerabilities based on actual runtime usage
- 📊 **VEX Generation** - Produce VEX documents for vulnerability management
- 🔄 **Registry Scanning** - Scan images directly from container registries
- ⚡ **Concurrent Processing** - Configurable parallel scanning for performance
- 📡 **OpenTelemetry Support** - Built-in observability and tracing

---

## Architecture

Kubevuln follows a **hexagonal (ports & adapters) architecture** for clean separation of concerns:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              KUBEVULN                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────┐     ┌─────────────────────┐     ┌─────────────────┐  │
│   │   HTTP      │     │                     │     │    Adapters     │  │
│   │ Controller  │────▶│    Core Services    │◀────│                 │  │
│   │  (Gin)      │     │    (ScanService)    │     │  ┌───────────┐  │  │
│   └─────────────┘     │                     │     │  │   Syft    │  │  │
│         │             │  ┌───────────────┐  │     │  │  (SBOM)   │  │  │
│         │             │  │    Ports      │  │     │  └───────────┘  │  │
│    REST API           │  │  (Interfaces) │  │     │                 │  │
│   ┌─────────────┐     │  └───────────────┘  │     │  ┌───────────┐  │  │
│   │  /v1/...    │     │                     │     │  │   Grype   │  │  │
│   └─────────────┘     └─────────────────────┘     │  │   (CVE)   │  │  │
│                                 │                 │  └───────────┘  │  │
│                                 ▼                 │                 │  │
│                       ┌─────────────────┐         │  ┌───────────┐  │  │
│                       │  Repositories   │         │  │  Backend  │  │  │
│                       │  (Storage)      │         │  │ Platform  │  │  │
│                       └─────────────────┘         │  └───────────┘  │  │
│                                │                  └─────────────────┘  │
│                                ▼                                       │
│                       ┌─────────────────┐                              │
│                       │   Kubernetes    │                              │
│                       │   API Server    │                              │
│                       └─────────────────┘                              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Overview

| Component | Description | Location |
|-----------|-------------|----------|
| **HTTP Controller** | REST API handlers using Gin | `controllers/` |
| **Core Services** | Business logic for scanning | `core/services/` |
| **Ports** | Interface definitions | `core/ports/` |
| **Domain** | Business entities and errors | `core/domain/` |
| **Adapters** | External tool integrations | `adapters/v1/` |
| **Repositories** | Storage implementations | `repositories/` |

---

## Quick Start

Get Kubevuln running locally in under 5 minutes.

### Prerequisites

- **Go 1.24+** ([installation guide](https://golang.org/doc/install))
- **Docker** (optional, for container builds)
- **kubectl** (optional, for Kubernetes deployment)

### 1. Clone and Build

```bash
git clone https://github.com/kubescape/kubevuln.git
cd kubevuln
make
```

### 2. Create Configuration

```bash
mkdir -p /tmp/kubevuln-config

cat > /tmp/kubevuln-config/clusterData.json << 'EOF'
{
  "keepLocal": true,
  "clusterName": "dev-cluster",
  "accountID": "local-dev"
}
EOF
```

### 3. Run Kubevuln

```bash
CONFIG_DIR=/tmp/kubevuln-config ./kubevuln
```

Expected output:
```
{"level":"info","ts":"...","msg":"starting server"}
```

### 4. Verify It's Running

```bash
curl http://localhost:8080/v1/liveness
```

Expected response:
```json
{"status":200,"title":"OK"}
```

---

## Installation

### In-Cluster Deployment (Recommended)

Kubevuln is typically deployed as part of the Kubescape operator. See the [Kubescape Helm chart](https://github.com/kubescape/helm-charts) for production deployment.

```bash
helm repo add kubescape https://kubescape.github.io/helm-charts
helm repo update
helm install kubescape kubescape/kubescape-operator -n kubescape --create-namespace
```

### Docker

```bash
# Build the image
make docker-build IMAGE=my-registry/kubevuln TAG=latest

# Push to registry
make docker-push IMAGE=my-registry/kubevuln TAG=latest
```

### From Source

```bash
# Build binary
make

# Or build directly with Go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kubevuln cmd/http/main.go
```

---

## Configuration

Kubevuln is configured via a JSON configuration file and environment variables.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_DIR` | Directory containing configuration files | `/etc/config` |
| `OTEL_COLLECTOR_SVC` | OpenTelemetry collector endpoint (e.g., `otel-collector:4317`) | _(disabled)_ |
| `RELEASE` | Version identifier for telemetry | _(empty)_ |

### Configuration File

Place a `clusterData.json` file in your `CONFIG_DIR`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `accountID` | string | _(required)_ | Account identifier for backend services |
| `clusterName` | string | _(required)_ | Name of the Kubernetes cluster |
| `keepLocal` | bool | `false` | If `true`, don't send reports to backend |
| `listingURL` | string | `https://grype.anchore.io/databases` | Grype vulnerability database URL |
| `maxImageSize` | int | `536870912` (512 MB) | Maximum image size to scan (bytes) |
| `maxSBOMSize` | int | `20971520` (20 MB) | Maximum SBOM size (bytes) |
| `namespace` | string | `kubescape` | Kubernetes namespace for storage |
| `nodeSbomGeneration` | bool | `false` | Enable node-level SBOM generation |
| `partialRelevancy` | bool | `false` | Enable partial relevancy matching |
| `scanConcurrency` | int | `1` | Number of concurrent scans |
| `scanEmbeddedSBOMs` | bool | `false` | Scan for embedded SBOMs in images |
| `scanTimeout` | duration | `5m` | Timeout for SBOM generation |
| `storage` | bool | `false` | Enable Kubernetes storage backend |
| `storeFilteredSbom` | bool | `false` | Store filtered SBOMs |
| `useDefaultMatchers` | bool | `false` | Use Grype default matchers (less CPE matching) |
| `vexGeneration` | bool | `false` | Enable VEX document generation |

### Example Configurations

<details>
<summary><strong>Minimal Local Development</strong></summary>

```json
{
  "keepLocal": true,
  "clusterName": "dev-cluster",
  "accountID": "local-dev"
}
```
</details>

<details>
<summary><strong>Production with Storage</strong></summary>

```json
{
  "accountID": "your-account-id",
  "clusterName": "production-cluster",
  "namespace": "kubescape",
  "storage": true,
  "scanConcurrency": 4,
  "scanTimeout": "10m",
  "maxImageSize": 1073741824,
  "vexGeneration": true
}
```
</details>

<details>
<summary><strong>High-Performance Scanning</strong></summary>

```json
{
  "accountID": "your-account-id",
  "clusterName": "large-cluster",
  "scanConcurrency": 8,
  "scanTimeout": "15m",
  "maxImageSize": 2147483648,
  "maxSBOMSize": 52428800,
  "useDefaultMatchers": true
}
```
</details>

### Backend Services Configuration

For integration with Kubescape backend services, create a `services.json` file in the same config directory:

```json
{
  "version": "v2",
  "services": {
    "apiServer": "https://api.your-backend.com",
    "reportReceiver": "https://report.your-backend.com"
  }
}
```

---

## API Reference

Kubevuln exposes a REST API on port **8080**.

### Health Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/liveness` | Liveness probe - returns 200 if server is running |
| `GET` | `/v1/readiness` | Readiness probe - returns 200 if vulnerability DB is loaded |

### Scan Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/sbomCreation` | Generate SBOM for a container image |
| `POST` | `/v1/scanImage` | Scan a container image for CVEs |
| `POST` | `/v1/scanRegistryImage` | Scan an image directly from a registry |
| `POST` | `/v1/applicationProfileScan` | Scan based on application profile |

### Request Format

All scan endpoints accept a `WebsocketScanCommand` JSON payload:

```json
{
  "imageTag": "nginx:1.24",
  "imageHash": "sha256:abc123...",
  "wlid": "wlid://cluster-name/namespace-default/deployment-nginx",
  "jobID": "unique-job-id",
  "containerName": "nginx",
  "args": {},
  "credentialslist": []
}
```

### Response Format

Responses use the RFC 7807 Problem Details format:

```json
{
  "status": 200,
  "title": "OK",
  "detail": "ImageHash=nginx@sha256:abc123..."
}
```

### Example: Scan an Image

```bash
curl -X POST http://localhost:8080/v1/scanImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "nginx:1.24",
    "imageHash": "sha256:abc123def456...",
    "wlid": "wlid://cluster-dev/namespace-default/deployment-nginx",
    "jobID": "scan-001"
  }'
```

For detailed API documentation, see [docs/API.md](docs/API.md).

---

## Development

### Project Structure

```
kubevuln/
├── adapters/           # External service adapters
│   └── v1/             # Syft, Grype, Backend adapters
├── api/                # API test data
├── build/              # Dockerfile
├── cmd/
│   ├── cli/            # CLI entrypoint (not yet implemented)
│   └── http/           # HTTP server entrypoint
├── config/             # Configuration loading
├── controllers/        # HTTP handlers
├── core/
│   ├── domain/         # Business entities
│   ├── ports/          # Interface definitions
│   └── services/       # Business logic
├── internal/           # Internal utilities
└── repositories/       # Storage implementations
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./core/services/...
```

### VS Code Setup

<details>
<summary><strong>.vscode/launch.json</strong></summary>

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Kubevuln",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceRoot}/cmd/http",
      "env": {
        "CONFIG_DIR": "${workspaceRoot}/.vscode",
        "NAMESPACE": "kubescape"
      },
      "args": ["-alsologtostderr", "-v=4"]
    }
  ]
}
```
</details>

<details>
<summary><strong>.vscode/clusterData.json</strong></summary>

```json
{
  "keepLocal": true,
  "clusterName": "vscode-dev",
  "accountID": "dev-account",
  "storage": false,
  "scanTimeout": "5m"
}
```
</details>

### Building Docker Image

```bash
# Build for local architecture
make docker-build

# Build with custom image name and tag
make docker-build IMAGE=myregistry/kubevuln TAG=v1.0.0

# Push to registry
make docker-push IMAGE=myregistry/kubevuln TAG=v1.0.0
```

---

## Troubleshooting

### Common Issues

<details>
<summary><strong>❌ "vulnerability DB is not initialized"</strong></summary>

**Cause:** The Grype vulnerability database hasn't been downloaded yet.

**Solution:** Wait for the readiness probe to succeed. The database is downloaded on first startup and refreshed every 24 hours.

```bash
# Check readiness
curl http://localhost:8080/v1/readiness
```
</details>

<details>
<summary><strong>❌ "SBOM exceeds size limit"</strong></summary>

**Cause:** The generated SBOM is larger than `maxSBOMSize`.

**Solution:** Increase `maxSBOMSize` in your configuration:

```json
{
  "maxSBOMSize": 52428800
}
```
</details>

<details>
<summary><strong>❌ "Image exceeds size limit"</strong></summary>

**Cause:** The container image is larger than `maxImageSize`.

**Solution:** Increase `maxImageSize` in your configuration:

```json
{
  "maxImageSize": 1073741824
}
```
</details>

<details>
<summary><strong>❌ "401 Unauthorized" when scanning private images</strong></summary>

**Cause:** Missing or invalid registry credentials.

**Solution:** Include credentials in the scan request:

```json
{
  "credentialslist": [
    {
      "username": "user",
      "password": "token",
      "serveraddress": "registry.example.com"
    }
  ]
}
```
</details>

<details>
<summary><strong>❌ Scans timing out</strong></summary>

**Cause:** Large images or slow network.

**Solution:** Increase `scanTimeout`:

```json
{
  "scanTimeout": "15m"
}
```
</details>

### Debug Logging

Enable verbose logging by setting log level:

```bash
# Using command-line flags
./kubevuln -alsologtostderr -v=4
```

### Getting Help

- 📖 [Kubescape Documentation](https://kubescape.io/docs/)
- 💬 [Slack Community](https://cloud-native.slack.com/archives/C04EY3ZF9GE)
- 🐛 [GitHub Issues](https://github.com/kubescape/kubevuln/issues)

---

## Contributing

We welcome contributions! Kubevuln is part of the Kubescape project.

### Quick Links

- [Contributing Guide](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./...`
5. Commit with clear messages: `git commit -m "Add feature X"`
6. Push and create a Pull Request

### Project Governance

- [Governance](https://github.com/kubescape/project-governance/blob/main/GOVERNANCE.md)
- [Maintainers](https://github.com/kubescape/project-governance/blob/main/MAINTAINERS.md)
- [Community](https://github.com/kubescape/project-governance/blob/main/COMMUNITY.md)

---

## License

Kubevuln is licensed under the [Apache License 2.0](LICENSE).

```
Copyright 2022-2024 Kubescape Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---

## Changelog

See the [Releases](https://github.com/kubescape/kubevuln/releases) page for version history and release notes.

---

<p align="center">
  <a href="https://kubescape.io">
    <img src="https://raw.githubusercontent.com/kubescape/kubescape/master/docs/img/kubescape-logo.png" alt="Kubescape" width="200">
  </a>
  <br>
  <em>Part of the <a href="https://github.com/kubescape/kubescape">Kubescape</a> security platform</em>
</p>