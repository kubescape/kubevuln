# Kubevuln Development Guide

This guide covers setting up a development environment, building, testing, and contributing to Kubevuln.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Building](#building)
- [Testing](#testing)
- [Debugging](#debugging)
- [Code Organization](#code-organization)
- [Development Workflow](#development-workflow)
- [Common Tasks](#common-tasks)
- [IDE Setup](#ide-setup)

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.24+ | Build and run |
| Git | 2.x+ | Source control |
| Make | 3.x+ | Build automation |
| Docker | 20.x+ | Container builds |

### Optional Tools

| Tool | Purpose |
|------|---------|
| kubectl | Kubernetes integration testing |
| kind/minikube | Local Kubernetes cluster |
| golangci-lint | Code linting |
| dlv | Go debugger |

### Install Go 1.24+

```bash
# Download (adjust version as needed)
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz

# Install
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Verify
go version
# Output: go version go1.24.1 linux/amd64
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/kubescape/kubevuln.git
cd kubevuln
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Create Development Configuration

```bash
mkdir -p .dev/config

cat > .dev/config/clusterData.json << 'EOF'
{
  "keepLocal": true,
  "clusterName": "dev-cluster",
  "accountID": "dev-account",
  "storage": false,
  "scanTimeout": "10m"
}
EOF
```

### 4. Build and Run

```bash
# Build
make

# Run
CONFIG_DIR=.dev/config ./kubevuln
```

### 5. Verify

```bash
# In another terminal
curl http://localhost:8080/v1/liveness
# {"status":200,"title":"OK"}

# Wait for readiness (DB download)
curl http://localhost:8080/v1/readiness
# {"status":200,"title":"OK"}
```

---

## Building

### Build Commands

```bash
# Build binary for current platform
make

# Build binary manually
CGO_ENABLED=0 go build -o kubevuln cmd/http/main.go

# Build for specific platform
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kubevuln cmd/http/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o kubevuln-arm64 cmd/http/main.go
```

### Docker Build

```bash
# Build Docker image
make docker-build

# Build with custom tag
make docker-build IMAGE=myregistry/kubevuln TAG=dev

# Multi-platform build (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t myregistry/kubevuln:dev \
  -f build/Dockerfile .
```

### Build Verification

```bash
# Check binary
./kubevuln --help

# Check size
ls -lh kubevuln

# Check dependencies (should be statically linked)
ldd kubevuln
# Output: not a dynamic executable
```

---

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run with coverage
go test -cover ./...

# Run with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run specific package
go test ./core/services/...

# Run specific test
go test -v -run TestScanService ./core/services/
```

### Test Categories

```bash
# Unit tests only (fast)
go test -short ./...

# Integration tests (requires external dependencies)
go test -tags=integration ./...
```

### Test Coverage

```
┌─────────────────────────────────────────────────────────────────┐
│                     Test Coverage Goals                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Package                          Target Coverage               │
│  ─────────────────────────────────────────────────              │
│  core/services/                   80%+                          │
│  core/domain/                     90%+                          │
│  controllers/                     70%+                          │
│  adapters/v1/                     60%+                          │
│  repositories/                    70%+                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Writing Tests

Example test structure:

```go
package services

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/kubescape/kubevuln/adapters"
    "github.com/kubescape/kubevuln/core/domain"
)

func TestScanService_GenerateSBOM(t *testing.T) {
    // Arrange
    mockSBOM := adapters.NewMockSBOMAdapter(false, false, false)
    mockCVE := adapters.NewMockCVEAdapter()
    mockPlatform := adapters.NewMockPlatform(true)
    
    service := NewScanService(
        mockSBOM,
        nil, // sbomRepository
        mockCVE,
        nil, // cveRepository
        mockPlatform,
        nil, // relevancyProvider
        false, // storage
        false, // vexGeneration
        true,  // skipNodeSbom
        false, // storeFilteredSbom
        false, // partialRelevancy
    )
    
    // Act
    ctx := context.Background()
    workload := domain.ScanCommand{
        ImageTag: "nginx:latest",
    }
    ctx, err := service.ValidateGenerateSBOM(ctx, workload)
    
    // Assert
    assert.NoError(t, err)
}

func TestScanService_GenerateSBOM_Error(t *testing.T) {
    tests := []struct {
        name        string
        wantError   bool
        errorMsg    string
    }{
        {
            name:      "missing image",
            wantError: true,
            errorMsg:  "missing image",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

---

## Debugging

### Local Debugging

```bash
# Run with debug logging
./kubevuln -alsologtostderr -v=4

# Or set environment variables
export GOLOG_LOG_LEVEL=debug
./kubevuln
```

### Using Delve Debugger

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug build (includes debug symbols)
go build -gcflags="all=-N -l" -o kubevuln cmd/http/main.go

# Start debugger
CONFIG_DIR=.dev/config dlv exec ./kubevuln

# Or debug directly
CONFIG_DIR=.dev/config dlv debug cmd/http/main.go
```

Common Delve commands:

```
(dlv) break main.main           # Set breakpoint
(dlv) break scan.go:100         # Break at line
(dlv) continue                  # Continue execution
(dlv) next                      # Step over
(dlv) step                      # Step into
(dlv) print varname             # Print variable
(dlv) goroutines                # List goroutines
(dlv) stack                     # Print stack trace
```

### Debugging Tests

```bash
# Debug a specific test
dlv test ./core/services/ -- -test.run TestScanService

# Run test with race detector
go test -race ./...
```

### Remote Debugging

```bash
# In container or remote machine
dlv exec --headless --listen=:2345 --api-version=2 ./kubevuln

# Connect from local machine
dlv connect localhost:2345
```

---

## Code Organization

### Package Structure

```
kubevuln/
├── adapters/                 # External service implementations
│   └── v1/                   # Version 1 adapters
│       ├── syft.go           # SBOM generation
│       ├── grype.go          # CVE scanning
│       └── backend.go        # Backend communication
│
├── cmd/
│   └── http/
│       └── main.go           # Application entry point
│
├── config/
│   └── config.go             # Configuration management
│
├── controllers/
│   └── http.go               # HTTP request handlers
│
├── core/
│   ├── domain/               # Business entities (no dependencies)
│   │   ├── cve.go
│   │   ├── sbom.go
│   │   └── scan.go
│   ├── ports/                # Interface definitions
│   │   ├── providers.go
│   │   ├── repositories.go
│   │   └── services.go
│   └── services/             # Business logic
│       └── scan.go
│
├── internal/
│   └── tools/                # Internal utilities
│
└── repositories/             # Storage implementations
    ├── apiserver.go
    └── memory.go
```

### Adding a New Feature

1. **Define domain types** in `core/domain/`
2. **Define port interface** in `core/ports/`
3. **Implement business logic** in `core/services/`
4. **Implement adapter** in `adapters/v1/`
5. **Add HTTP endpoint** in `controllers/`
6. **Wire up in** `cmd/http/main.go`
7. **Add tests** alongside each component

---

## Development Workflow

### Typical Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Development Workflow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Create branch                                                │
│     └── git checkout -b feature/my-feature                       │
│                                                                  │
│  2. Make changes                                                 │
│     └── Edit files, add tests                                    │
│                                                                  │
│  3. Run tests                                                    │
│     └── go test ./...                                           │
│                                                                  │
│  4. Run linter                                                   │
│     └── golangci-lint run                                        │
│                                                                  │
│  5. Build and verify                                             │
│     └── make && CONFIG_DIR=.dev/config ./kubevuln               │
│                                                                  │
│  6. Commit changes                                               │
│     └── git commit -m "Add feature X"                           │
│                                                                  │
│  7. Push and create PR                                           │
│     └── git push origin feature/my-feature                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Code Style

```bash
# Format code
go fmt ./...

# Run linter
golangci-lint run

# Fix common issues
golangci-lint run --fix
```

### Pre-commit Checks

```bash
#!/bin/bash
# .git/hooks/pre-commit

set -e

echo "Running go fmt..."
go fmt ./...

echo "Running go vet..."
go vet ./...

echo "Running tests..."
go test -short ./...

echo "All checks passed!"
```

---

## Common Tasks

### Adding a New Adapter

1. Create interface in `core/ports/providers.go`:

```go
type MyProvider interface {
    DoSomething(ctx context.Context, input string) (string, error)
}
```

2. Implement adapter in `adapters/v1/`:

```go
type MyAdapter struct {
    // fields
}

var _ ports.MyProvider = (*MyAdapter)(nil)

func NewMyAdapter() *MyAdapter {
    return &MyAdapter{}
}

func (a *MyAdapter) DoSomething(ctx context.Context, input string) (string, error) {
    // implementation
}
```

3. Create mock in `adapters/`:

```go
type MockMyAdapter struct {
    // fields for controlling behavior
}

var _ ports.MyProvider = (*MockMyAdapter)(nil)
```

### Adding a New API Endpoint

1. Add handler in `controllers/http.go`:

```go
func (h HTTPController) MyEndpoint(c *gin.Context) {
    ctx := c.Request.Context()
    
    var request MyRequest
    if err := c.ShouldBindJSON(&request); err != nil {
        _, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
        return
    }
    
    // Process request
    _, _ = problem.Of(http.StatusOK).WriteTo(c.Writer)
}
```

2. Register route in `cmd/http/main.go`:

```go
group.POST("/myEndpoint", controller.MyEndpoint)
```

3. Add tests in `controllers/http_test.go`

### Updating Dependencies

```bash
# Update all dependencies
go get -u ./...

# Update specific dependency
go get -u github.com/anchore/grype@latest

# Tidy modules
go mod tidy

# Verify
go mod verify
```

---

## IDE Setup

### VS Code

#### Extensions

- Go (official)
- Go Test Explorer
- GitLens

#### settings.json

```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "go.testFlags": ["-v"],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  }
}
```

#### launch.json

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Kubevuln",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}/cmd/http",
      "env": {
        "CONFIG_DIR": "${workspaceFolder}/.dev/config"
      },
      "args": ["-alsologtostderr", "-v=4"]
    },
    {
      "name": "Test Current Package",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${fileDirname}"
    },
    {
      "name": "Debug Current Test",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${fileDirname}",
      "args": ["-test.run", "${selectedText}"]
    }
  ]
}
```

#### clusterData.json for VS Code

```json
{
  "keepLocal": true,
  "clusterName": "vscode-dev",
  "accountID": "dev-account",
  "storage": false,
  "scanTimeout": "10m"
}
```

### GoLand / IntelliJ IDEA

1. Open project: `File > Open > Select kubevuln directory`
2. Configure Go SDK: `File > Project Structure > SDKs`
3. Run configuration:
   - Type: Go Build
   - Run kind: Directory
   - Directory: `cmd/http`
   - Environment: `CONFIG_DIR=/path/to/kubevuln/.dev/config`

### Vim/Neovim

With vim-go or gopls:

```vim
" .vimrc or init.vim
let g:go_fmt_command = "goimports"
let g:go_auto_type_info = 1
let g:go_def_mode='gopls'
let g:go_info_mode='gopls'
```

---

## Troubleshooting Development Issues

### Common Issues

| Issue | Solution |
|-------|----------|
| `go mod download` fails | Check network, try `GOPROXY=direct go mod download` |
| Tests hang | Check for missing mocks, use `go test -timeout 30s` |
| Build fails with CGO errors | Ensure `CGO_ENABLED=0` |
| Grype DB download fails | Check network, or use `keepLocal: true` |

### Cleaning Up

```bash
# Clean build artifacts
rm -f kubevuln

# Clean Go cache
go clean -cache

# Clean test cache
go clean -testcache

# Clean module cache (careful!)
go clean -modcache

# Clean Grype DB
rm -rf ~/.cache/grype
```

---

## See Also

- [README.md](../README.md) - Main documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - Architecture details
- [Contributing Guide](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md)