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
| Graceful shutdown | Waits for in-flight scans to complete |
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
│   │   ├── syft.go             # SBOM generation using Syft
│   │   ├── grype.go            # CVE scanning using Grype
│   │   ├── backend.go          # Kubescape backend communication
│   │   └── container_profile.go # Relevancy provider
│   ├── mockcve.go              # Mock CVE scanner for testing
│   ├── mockplatform.go         # Mock platform for testing
│   └── mocksbom.go             # Mock SBOM creator for testing
│
├── cmd/
│   ├── http/
│   │   └── main.go             # HTTP server entry point
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
│   └── tools/                  # Internal utilities
│
└── repositories/
    ├── apiserver.go            # Kubernetes API server storage
    ├── memory.go               # In-memory storage
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