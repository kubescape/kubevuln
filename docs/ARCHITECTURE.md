# Kubevuln Architecture

This document describes the internal architecture of Kubevuln, its components, and how they interact.

---

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [System Architecture](#system-architecture)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Scanning Pipeline](#scanning-pipeline)
- [Storage Architecture](#storage-architecture)
- [Integration Points](#integration-points)

---

## Overview

Kubevuln is designed as an in-cluster vulnerability scanning service that:

1. Receives scan requests via REST API
2. Downloads and analyzes container images
3. Generates Software Bill of Materials (SBOMs)
4. Scans SBOMs for known vulnerabilities (CVEs)
5. Reports results to the Kubescape platform

---

## Design Principles

### Hexagonal Architecture (Ports & Adapters)

Kubevuln follows the hexagonal architecture pattern to achieve:

- **Separation of concerns** - Business logic is isolated from external dependencies
- **Testability** - Core services can be tested with mock adapters
- **Flexibility** - External tools (Syft, Grype) can be swapped without changing business logic
- **Maintainability** - Clear boundaries between components

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                                                              │
    ┌───────────┐   │   ┌─────────────┐        ┌──────────────┐        ┌───────┐ │
    │           │   │   │             │        │              │        │       │ │
    │  HTTP     │───┼──▶│  Controllers│───────▶│    Core      │◀───────│ Ports │ │
    │  Client   │   │   │             │        │   Services   │        │       │ │
    │           │   │   └─────────────┘        │              │        └───┬───┘ │
    └───────────┘   │                          └──────┬───────┘            │     │
                    │                                 │                    │     │
                    │                                 ▼                    ▼     │
                    │                          ┌──────────────┐     ┌──────────┐ │
                    │                          │   Domain     │     │ Adapters │ │
                    │                          │   Entities   │     │          │ │
                    │                          └──────────────┘     └────┬─────┘ │
                    │                                                    │       │
                    └────────────────────────────────────────────────────┼───────┘
                                                                         │
                    ┌────────────────────────────────────────────────────┼───────┐
                    │                    External Systems                │       │
                    │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────▼─────┐ │
                    │  │  Syft   │  │  Grype  │  │ K8s API │  │    Backend    │ │
                    │  │         │  │         │  │ Server  │  │    Platform   │ │
                    │  └─────────┘  └─────────┘  └─────────┘  └───────────────┘ │
                    └───────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Async processing | Scan requests return immediately; work is queued |
| Worker pool | Prevents resource exhaustion with concurrent scans |
| Queue admission control | `maxQueueDepth` (default unbounded) rejects new scans with `503` once too many are queued/running, instead of growing the backlog without limit |
| Graceful shutdown | Abandons queued scans and waits for in-flight scans to complete, bounded by `shutdownTimeout` |
| Modular adapters | Easy to upgrade Syft/Grype versions |
| Interface-driven | All external dependencies accessed via ports |

---

## System Architecture

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                    KUBERNETES CLUSTER                                 │
│                                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              KUBESCAPE NAMESPACE                                 │ │
│  │                                                                                  │ │
│  │  ┌─────────────┐     ┌─────────────────┐     ┌─────────────────────────────────┐│ │
│  │  │             │     │                 │     │           KUBEVULN              ││ │
│  │  │  Operator   │────▶│    Gateway      │────▶│                                 ││ │
│  │  │             │     │                 │     │  ┌─────────────────────────┐   ││ │
│  │  └─────────────┘     └─────────────────┘     │  │      HTTP Server        │   ││ │
│  │         │                                    │  │      (port 8080)        │   ││ │
│  │         │                                    │  └───────────┬─────────────┘   ││ │
│  │         ▼                                    │              │                 ││ │
│  │  ┌─────────────┐                             │              ▼                 ││ │
│  │  │   Storage   │◀────────────────────────────│  ┌─────────────────────────┐   ││ │
│  │  │   (CRDs)    │                             │  │     Worker Pool         │   ││ │
│  │  │             │                             │  │  ┌─────┐ ┌─────┐        │   ││ │
│  │  │ - SBOMs     │                             │  │  │Scan │ │Scan │ ...    │   ││ │
│  │  │ - CVEs      │                             │  │  │  1  │ │  2  │        │   ││ │
│  │  │ - VEX       │                             │  │  └─────┘ └─────┘        │   ││ │
│  │  └─────────────┘                             │  └─────────────────────────┘   ││ │
│  │                                              │              │                 ││ │
│  │                                              │              ▼                 ││ │
│  │                                              │  ┌─────────────────────────┐   ││ │
│  │                                              │  │    Grype DB Cache       │   ││ │
│  │                                              │  │    (~/.cache/grype)     │   ││ │
│  │                                              │  └─────────────────────────┘   ││ │
│  │                                              └─────────────────────────────────┘│ │
│  └──────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                       │
└───────────────────────────────────────────────────────────────────────────────────────┘
                │                               │                         │
                ▼                               ▼                         ▼
        ┌───────────────┐             ┌─────────────────┐        ┌───────────────┐
        │   Container   │             │     Grype       │        │   Kubescape   │
        │  Registries   │             │   Vuln DB       │        │    Backend    │
        └───────────────┘             └─────────────────┘        └───────────────┘
```

### Component Interaction

```
                                  Request Flow
                                  ════════════

     ┌──────────┐         ┌────────────┐         ┌─────────────┐
     │  Client  │────────▶│ Controller │────────▶│   Service   │
     └──────────┘         └────────────┘         └─────────────┘
          │                     │                      │
          │                     │                      │
    1. POST /v1/scanImage       │                      │
          │                     │                      │
          │              2. Validate &                 │
          │                 Enqueue                    │
          │                     │                      │
          │                     │               3. Process
          │                     │                  (async)
          │                     │                      │
          │              4. Return 200                 │
          │◀────────────────────│                      │
          │                                            │
          │                                            ▼
          │                               ┌────────────────────┐
          │                               │  Generate SBOM     │
          │                               │  (Syft Adapter)    │
          │                               └─────────┬──────────┘
          │                                         │
          │                                         ▼
          │                               ┌────────────────────┐
          │                               │  Scan for CVEs     │
          │                               │  (Grype Adapter)   │
          │                               └─────────┬──────────┘
          │                                         │
          │                                         ▼
          │                               ┌────────────────────┐
          │                               │  Store Results     │
          │                               │  (Repository)      │
          │                               └─────────┬──────────┘
          │                                         │
          │                                         ▼
          │                               ┌────────────────────┐
          │                               │  Report to Backend │
          │                               │  (Platform)        │
          │                               └────────────────────┘
```

---

## Component Details

### Directory Structure

```
kubevuln/
├── adapters/                    # External service implementations
│   ├── v1/
│   │   ├── syft.go             # SBOM generation using Syft, in-process
│   │   ├── sidecar.go          # SBOM generation via the sbom-scanner sidecar
│   │   ├── grype.go            # CVE scanning using Grype
│   │   ├── backend.go          # Kubescape backend communication
│   │   ├── securityexception.go # SecurityException CRDs -> exception policies
│   │   └── container_profile.go # Relevancy provider
│   ├── mockcve.go              # Mock CVE scanner for testing
│   ├── mockplatform.go         # Mock platform for testing
│   └── mocksbom.go             # Mock SBOM creator for testing
│
├── cmd/
│   ├── http/
│   │   └── main.go             # HTTP server entry point
│   ├── sbom-scanner/
│   │   └── main.go             # Sidecar SBOM scanner entry point (gRPC over a Unix socket)
│   └── cli/
│       └── main.go             # CLI entry point (not implemented)
│
├── config/
│   └── config.go               # Configuration loading
│
├── controllers/
│   └── http.go                 # HTTP request handlers
│
├── core/
│   ├── domain/                 # Business entities
│   │   ├── cve.go              # CVE manifest types
│   │   ├── sbom.go             # SBOM types
│   │   ├── scan.go             # Scan command types
│   │   └── platform.go         # Platform report types
│   │
│   ├── ports/                  # Interface definitions
│   │   ├── providers.go        # Provider interfaces
│   │   ├── repositories.go     # Repository interfaces
│   │   └── services.go         # Service interfaces
│   │
│   └── services/
│       └── scan.go             # Main scanning business logic
│
├── internal/
│   ├── tools/                  # Internal utilities
│   ├── metrics/                # OpenTelemetry instruments and recorders
│   ├── registryauth/           # Registry credential resolution, shared by both SBOM paths
│   ├── syftmeta/               # Syft metadata reattachment
│   ├── safefetch/              # SSRF-guarded HTTPS fetcher for user-supplied URLs
│   └── vexdoc/                 # Safe temp-file writer for VEX documents
│
├── pkg/                        # Importable by other projects
│   ├── sbomscanner/v1/         # Sidecar scanner protocol: gRPC client, server, proto
│   └── securityexception/v1beta1/ # SecurityException / ClusterSecurityException CRD types
│
└── repositories/
    ├── apiserver.go            # Kubernetes API server storage
    ├── memory.go               # In-memory storage (testing)
    └── broken.go               # Always-failing storage (testing)
```

### Core Components

#### 1. HTTP Controller (`controllers/http.go`)

Responsibilities:
- Parse incoming HTTP requests
- Validate request payloads
- Enqueue work to the worker pool
- Return immediate responses

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP Controller                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Endpoints:                                                  │
│  ├── GET  /v1/liveness   → Alive()                          │
│  ├── GET  /v1/readiness  → Ready()                          │
│  ├── GET  /metrics       → Prometheus exposition            │
│  ├── POST /v1/sbomCreation           → GenerateSBOM()       │
│  ├── POST /v1/scanImage              → ScanCVE()            │
│  ├── POST /v1/scanRegistryImage      → ScanRegistry()       │
│  └── POST /v1/applicationProfileScan → ScanCP()             │
│                                                              │
│  Worker Pool:                                                │
│  └── Concurrent scan processing (configurable)              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 2. Scan Service (`core/services/scan.go`)

The central business logic component implementing the `ScanService` port.

```
┌─────────────────────────────────────────────────────────────┐
│                      Scan Service                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Dependencies (injected via ports):                          │
│  ├── SBOMCreator      → Creates SBOMs from images           │
│  ├── CVEScanner       → Scans SBOMs for vulnerabilities     │
│  ├── SBOMRepository   → Stores/retrieves SBOMs              │
│  ├── CVERepository    → Stores/retrieves CVE results        │
│  ├── Platform         → Reports to backend                  │
│  └── Relevancy        → Provides relevancy information      │
│                                                              │
│  Operations:                                                 │
│  ├── GenerateSBOM()   → Create SBOM for image               │
│  ├── ScanCVE()        → Full vulnerability scan             │
│  ├── ScanRegistry()   → Registry-only scan                  │
│  ├── ScanCP()         → Container profile scan              │
│  └── Ready()          → Check service readiness             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 3. Adapters

**Syft Adapter** (`adapters/v1/syft.go`)
- Downloads container images from registries
- Generates SBOMs using Syft library
- Handles image size limits and timeouts
- Supports multiple registry authentication methods

**Sidecar SBOM Adapter** (`adapters/v1/sidecar.go`)
- Implements the same `SBOMCreator` port as the Syft adapter, so the scan service is unaware of which one it holds
- Delegates SBOM generation to the `sbom-scanner` sidecar over gRPC on a Unix domain socket, instead of running Syft in this process
- Attempted at startup when `SBOM_SCANNER_SOCKET` is set, and selected only once the sidecar passes its readiness check; startup falls back to the Syft adapter if it does not. See [SBOM Generation Modes](#sbom-generation-modes)

**Grype Adapter** (`adapters/v1/grype.go`)
- Manages vulnerability database updates
- Scans SBOMs for CVEs using Grype library
- Configurable matching strategies
- Daily database refresh

**Backend Adapter** (`adapters/v1/backend.go`)
- Sends scan results to Kubescape backend
- Handles authentication
- Reports errors and status updates

#### 4. Repositories

**API Server Store** (`repositories/apiserver.go`)
- Stores SBOMs as `SBOMSyft` CRDs
- Stores CVE results as `VulnerabilityManifest` CRDs
- Stores VEX documents as `OpenVulnerabilityExchangeContainer` CRDs

**Memory Store** (`repositories/memory.go`)
- In-memory storage for testing
- Used with `keepLocal: true`

---

### SBOM Generation Modes

SBOM generation runs in one of two places, chosen once at startup. Both implement the same
`SBOMCreator` port, so nothing downstream of `ScanService` behaves differently.

**In-process** (default). `SyftAdapter` runs Syft inside the kubevuln process. This is what
runs when `SBOM_SCANNER_SOCKET` is unset.

**Sidecar.** Setting `SBOM_SCANNER_SOCKET` points kubevuln at a second binary, `cmd/sbom-scanner`,
running as another container in the same pod. It serves the gRPC service in `pkg/sbomscanner/v1`
over a Unix domain socket, and `SidecarSBOMAdapter` calls it in place of running Syft locally.

The reason for the split is memory. Syft's peak usage scales with image size and is hard to bound
in advance, so a large image can exhaust the container's memory limit. In the sidecar, the kernel
kills that container instead of kubevuln, and the HTTP server, the scan queue and the Grype
database stay up.

```
┌──────────────────────────┐        ┌────────────────────────────┐
│ kubevuln container       │        │ sbom-scanner container     │
│                          │        │                            │
│  SidecarSBOMAdapter ─────┼── gRPC ┼──> scannerServer           │
│                          │  (uds) │      └─ syft.CreateSBOM    │
│  GrypeAdapter            │        │                            │
│  HTTP controller         │        │  OOM here does not take    │
│                          │        │  kubevuln down             │
└──────────────────────────┘        └────────────────────────────┘
```

Startup is fail-soft: `NewSBOMScannerClient` health-checks the sidecar, bounded by
`scannerReadinessTimeout`, and if it never becomes ready kubevuln logs the failure and falls back
to the in-process adapter rather than refusing to start. The mode actually in effect is reported
by `/v1/diagnostics` as `scanMode`.

Two consequences worth knowing when reading the code:

- The two paths are separate implementations of the same behaviour, so a change to one usually
  needs the same change to the other. Shared pieces have been factored out where practical, for
  example `internal/registryauth` for the credential fallback ladder.
- Concurrency differs. The in-process adapter serialises pulls behind a mutex so concurrent scans
  cannot exhaust local disk; the sidecar intentionally does not, and bounds in-flight work by the
  caller's `scanConcurrency` instead.

Relevant env vars: `SBOM_SCANNER_SOCKET` selects the mode on the kubevuln side; `SOCKET_PATH`
and `METRICS_ADDR` configure the sidecar; `SCANNER_MEMORY_LIMIT` is read at startup and passed
to the adapter, which records it on an SBOM it reports as too large for the scanner.

## Data Flow

### SBOM Generation Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          SBOM Generation Pipeline                           │
└────────────────────────────────────────────────────────────────────────────┘

    ┌─────────┐     ┌─────────────┐     ┌──────────────┐     ┌────────────┐
    │ Request │────▶│  Validate   │────▶│   Download   │────▶│  Generate  │
    │         │     │   Image     │     │    Image     │     │    SBOM    │
    └─────────┘     └─────────────┘     └──────────────┘     └────────────┘
                           │                   │                    │
                           │                   │                    │
                    ┌──────▼──────┐     ┌──────▼──────┐      ┌──────▼──────┐
                    │ Check size  │     │  Registry   │      │   Syft      │
                    │   limits    │     │   auth      │      │  cataloger  │
                    └─────────────┘     └─────────────┘      └─────────────┘
                                                                    │
                                                                    ▼
    ┌────────────┐     ┌─────────────┐     ┌──────────────┐  ┌────────────┐
    │   Report   │◀────│    Store    │◀────│   Convert    │◀─│   Check    │
    │  Complete  │     │    SBOM     │     │   Format     │  │   Size     │
    └────────────┘     └─────────────┘     └──────────────┘  └────────────┘
```

### CVE Scanning Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CVE Scanning Pipeline                              │
└────────────────────────────────────────────────────────────────────────────┘

    ┌─────────┐     ┌─────────────┐     ┌──────────────┐     ┌────────────┐
    │ Request │────▶│   Lookup    │────▶│    Scan      │────▶│  Filter    │
    │         │     │    SBOM     │     │    CVEs      │     │ Relevancy  │
    └─────────┘     └─────────────┘     └──────────────┘     └────────────┘
                           │                   │                    │
                           │                   │                    │
                    ┌──────▼──────┐     ┌──────▼──────┐      ┌──────▼──────┐
                    │  Generate   │     │   Grype     │      │  Container  │
                    │  if missing │     │   matcher   │      │   profile   │
                    └─────────────┘     └─────────────┘      └─────────────┘
                                                                    │
                                                                    ▼
    ┌────────────┐     ┌─────────────┐     ┌──────────────┐  ┌────────────┐
    │   Report   │◀────│    Store    │◀────│  Generate    │◀─│  Compile   │
    │  to Backend│     │    CVEs     │     │    VEX       │  │  Results   │
    └────────────┘     └─────────────┘     └──────────────┘  └────────────┘
```

---

## Scanning Pipeline

### Detailed Scan Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Vulnerability Scan Workflow                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. VALIDATION PHASE                                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Parse scan command                                                   │ │
│  │  • Validate image reference                                             │ │
│  │  • Generate scan ID                                                     │ │
│  │  • Add timestamp                                                        │ │
│  │  • Store in context                                                     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  2. SBOM PHASE                                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Check if SBOM exists in storage                                      │ │
│  │     ├── YES: Validate not outdated → Use existing                       │ │
│  │     └── NO:  Generate new SBOM                                          │ │
│  │              ├── Download image from registry                           │ │
│  │              ├── Run Syft cataloger                                     │ │
│  │              ├── Check size limits                                      │ │
│  │              └── Store SBOM                                             │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  3. CVE SCAN PHASE                                                           │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Load SBOM into Grype                                                 │ │
│  │  • Match packages against vulnerability DB                              │ │
│  │  • Apply matchers (language-specific + CPE)                             │ │
│  │  • Compile matches                                                      │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  4. RELEVANCY PHASE (optional)                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Fetch container profile                                              │ │
│  │  • Identify loaded packages                                             │ │
│  │  • Filter SBOM to relevant packages                                     │ │
│  │  • Re-scan filtered SBOM                                                │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  5. VEX PHASE (optional)                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Generate VEX document                                                │ │
│  │  • Include relevancy status                                             │ │
│  │  • Store VEX                                                            │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  6. REPORTING PHASE                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  • Store CVE manifest                                                   │ │
│  │  • Send results to backend platform                                     │ │
│  │  • Update scan status                                                   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Storage Architecture

### Kubernetes CRD Storage

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Storage Model                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      Custom Resource Definitions                      │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │  SBOMSyft (spdx.softwarecomposition.kubescape.io)                    │    │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │    │
│  │  │  metadata:                                                       │ │    │
│  │  │    name: <image-slug>                                            │ │    │
│  │  │    namespace: kubescape                                          │ │    │
│  │  │    annotations:                                                  │ │    │
│  │  │      kubescape.io/image-id: <image-digest>                       │ │    │
│  │  │      kubescape.io/image-tag: <image-tag>                         │ │    │
│  │  │  spec:                                                           │ │    │
│  │  │    syft: <SBOM content in Syft JSON format>                      │ │    │
│  │  └─────────────────────────────────────────────────────────────────┘ │    │
│  │                                                                       │    │
│  │  VulnerabilityManifest (spdx.softwarecomposition.kubescape.io)       │    │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │    │
│  │  │  metadata:                                                       │ │    │
│  │  │    name: <image-slug>                                            │ │    │
│  │  │  spec:                                                           │ │    │
│  │  │    payload: <Grype scan results>                                 │ │    │
│  │  └─────────────────────────────────────────────────────────────────┘ │    │
│  │                                                                       │    │
│  │  OpenVulnerabilityExchangeContainer (spdx.softwarecomposition...)    │    │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │    │
│  │  │  metadata:                                                       │ │    │
│  │  │    name: <image-slug>                                            │ │    │
│  │  │  spec:                                                           │ │    │
│  │  │    statements: <VEX statements>                                  │ │    │
│  │  └─────────────────────────────────────────────────────────────────┘ │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Vulnerability Database

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Grype Vulnerability Database                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Location: ~/.cache/grype/db/                                                │
│                                                                              │
│  Update Cycle:                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  1. Check lastDbUpdate timestamp                                     │    │
│  │  2. If > 24 hours, trigger update                                    │    │
│  │  3. Download from listingURL                                         │    │
│  │  4. Verify and install                                               │    │
│  │  5. Update lastDbUpdate                                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Failure Handling:                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Clean corrupted DB directory                                      │    │
│  │  • Exit process (Kubernetes will restart)                            │    │
│  │  • Fresh download on restart                                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## In-Process Caching

Kubevuln keeps three TTL caches in memory, all backed by `github.com/akyoto/cache`:

| Cache | Location | TTL | Purpose |
|-------|----------|-----|---------|
| `tooManyRequests` | `core/services/scan.go` | 10m | Registry rate-limit (429) backoff, keyed by image reference |
| `exceptionsCache` | `adapters/v1/backend.go` | 1m | Merged CVE-exceptions/VEX policy, keyed per workload |
| `securityExceptionListCache` | `repositories/apiserver.go` | 30s | Raw `SecurityException`/`ClusterSecurityException` `List()` results, keyed per namespace/cluster |

**These caches are process-local by design, not shared across replicas.** In a multi-replica Kubevuln deployment (see #438 for the equivalent discussion about the Grype vulnerability DB), each pod keeps an independent copy of each cache with no cross-pod coordination:

- A 429 recorded by one pod's `tooManyRequests` cache is invisible to the others - they can each independently discover and cache the same backoff, so the mitigation this cache exists to provide only fully applies within a single pod.
- A `SecurityException` change (create/update/delete) observed by one pod is not reflected on the others until their own cache entries naturally expire - the same workload can show a CVE as suppressed or not depending on which pod happens to handle a given scan request, for up to the relevant cache's TTL.

This is an accepted tradeoff, not an oversight: introducing a shared backing store (e.g. an external KV store) is a real architectural change with its own operational cost, and the deployment-side wiring for anything like that lives outside this repo (see kubescape-operator/helm-charts), matching how #438 scoped the equivalent Grype-DB-cache decision. Given that, the TTLs above are chosen deliberately per cache's actual stakes: `securityExceptionListCache` and `exceptionsCache` are kept short (30s / 1m) because a stale read there is a suppression-correctness question, not just a performance one, while `tooManyRequests` can tolerate a longer window (10m) since its only cost is a redundant registry pull attempt.

If this tradeoff ever needs to change (e.g. Kubevuln starts running at a replica count where the redundant-429 or suppression-disagreement window becomes a real operational problem), the right first step is `exceptionsCache`, since it's the one with actual correctness/security stakes rather than a pure performance cost.

---

## Integration Points

### External System Integration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Integration Architecture                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────┐                                                       │
│  │ Container         │  Pull images for scanning                             │
│  │ Registries        │◀─────────────────────────────────────┐               │
│  │ (Docker Hub,      │                                      │               │
│  │  GCR, ECR, etc.)  │                                      │               │
│  └───────────────────┘                                      │               │
│                                                              │               │
│  ┌───────────────────┐                                      │               │
│  │ Grype             │  Fetch vulnerability data            │               │
│  │ Vulnerability DB  │◀─────────────────────────────┐      │               │
│  │                   │                              │      │               │
│  └───────────────────┘                              │      │               │
│                                                     │      │               │
│  ┌───────────────────┐                        ┌─────┴──────┴─────┐         │
│  │ Kubernetes        │  Store scan results    │                  │         │
│  │ API Server        │◀──────────────────────▶│    KUBEVULN      │         │
│  │                   │                        │                  │         │
│  └───────────────────┘                        └─────┬──────┬─────┘         │
│                                                     │      │               │
│  ┌───────────────────┐                              │      │               │
│  │ Kubescape         │  Report scan results         │      │               │
│  │ Backend           │◀─────────────────────────────┘      │               │
│  │                   │                                      │               │
│  └───────────────────┘                                      │               │
│                                                              │               │
│  ┌───────────────────┐                                      │               │
│  │ OpenTelemetry     │  Send traces and metrics             │               │
│  │ Collector         │◀─────────────────────────────────────┘               │
│  │                   │                                                       │
│  └───────────────────┘                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Kubescape Ecosystem Integration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubescape Ecosystem                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                 │
│   │  Kubescape  │      │   Gateway   │      │  Operator   │                 │
│   │    CLI      │─────▶│             │◀─────│             │                 │
│   └─────────────┘      └──────┬──────┘      └──────┬──────┘                 │
│                               │                    │                         │
│                               ▼                    ▼                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                                                                      │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │   │
│   │  │  KUBEVULN   │  │   Storage   │  │  Node       │  │  Kollector  │ │   │
│   │  │             │  │             │  │  Agent      │  │             │ │   │
│   │  │ Vuln Scan   │  │ SBOM/CVE    │  │ Runtime     │  │ Resource    │ │   │
│   │  │             │  │ Storage     │  │ Profiles    │  │ Collection  │ │   │
│   │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────┘ │   │
│   │         │                │                │                          │   │
│   │         └────────────────┼────────────────┘                          │   │
│   │                          │                                           │   │
│   │                          ▼                                           │   │
│   │  ┌─────────────────────────────────────────────────────────────────┐│   │
│   │  │                    Kubernetes API Server                         ││   │
│   │  │                    (Custom Resources)                            ││   │
│   │  └─────────────────────────────────────────────────────────────────┘│   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## See Also

- [README.md](../README.md) - Main documentation
- [API.md](API.md) - API reference
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration guide
- [Kubescape Architecture](https://kubescape.io/docs/architecture/)