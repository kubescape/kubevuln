# Contributing to Kubevuln

Thank you for your interest in contributing to Kubevuln! This document provides guidelines and information for contributors.

---

## Table of Contents

- [Quick Links](#quick-links)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Code Guidelines](#code-guidelines)
- [Testing Requirements](#testing-requirements)
- [Getting Help](#getting-help)

---

## Quick Links

| Resource | Link |
|----------|------|
| **Centralized Contributing Guide** | [kubescape/project-governance/CONTRIBUTING.md](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md) |
| **Code of Conduct** | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| **Security Policy** | [SECURITY.md](SECURITY.md) |
| **Development Guide** | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| **Architecture** | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |

> **Note:** Kubevuln follows the centralized Kubescape project governance. Please review the [centralized CONTRIBUTING.md](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md) for general contribution guidelines.

---

## Getting Started

### Prerequisites

- **Go 1.24+** - [Installation guide](https://golang.org/doc/install)
- **Git** - For source control
- **Docker** - For container builds (optional)
- **Make** - For build automation

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/kubevuln.git
cd kubevuln
git remote add upstream https://github.com/kubescape/kubevuln.git
```

---

## Development Setup

### 1. Install Dependencies

```bash
go mod download
```

### 2. Create Development Config

```bash
mkdir -p .dev/config

cat > .dev/config/clusterData.json << 'EOF'
{
  "keepLocal": true,
  "clusterName": "dev-cluster",
  "accountID": "dev-account"
}
EOF
```

### 3. Build and Run

```bash
make
CONFIG_DIR=.dev/config ./kubevuln
```

### 4. Verify

```bash
curl http://localhost:8080/v1/liveness
# Expected: {"status":200,"title":"OK"}
```

For detailed development instructions, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

---

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-new-scanner` - New features
- `fix/sbom-timeout-issue` - Bug fixes
- `docs/update-api-docs` - Documentation
- `refactor/cleanup-adapters` - Code refactoring

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `test` - Tests
- `refactor` - Code refactoring
- `chore` - Maintenance

**Examples:**

```bash
git commit -m "feat(scanner): add support for SPDX SBOM format"
git commit -m "fix(grype): handle database update timeout"
git commit -m "docs(api): add examples for registry scanning"
```

---

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests:**
   ```bash
   go test ./...
   ```

3. **Run linter:**
   ```bash
   go fmt ./...
   go vet ./...
   ```

4. **Update documentation** if needed

### PR Requirements

- [ ] Tests pass (`go test ./...`)
- [ ] Code is formatted (`go fmt ./...`)
- [ ] No vet errors (`go vet ./...`)
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow convention
- [ ] PR description explains the change

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring

## Testing
How was this tested?

## Related Issues
Fixes #123
```

---

## Code Guidelines

### Project Structure

```
kubevuln/
├── adapters/v1/     # External service implementations
├── cmd/http/        # Application entry point
├── config/          # Configuration
├── controllers/     # HTTP handlers
├── core/
│   ├── domain/      # Business entities (no deps)
│   ├── ports/       # Interfaces
│   └── services/    # Business logic
└── repositories/    # Storage implementations
```

### Design Principles

1. **Hexagonal Architecture** - Keep business logic in `core/services`, external dependencies in `adapters/`

2. **Interface-Driven** - Define interfaces in `core/ports/`, implement in `adapters/`

3. **Testability** - Use dependency injection, create mocks for testing

4. **Error Handling** - Return errors, don't panic; use domain errors from `core/domain/`

### Code Style

```go
// Good: Clear function with error handling
func (s *ScanService) ScanImage(ctx context.Context, image string) (*domain.CVEManifest, error) {
    if image == "" {
        return nil, domain.ErrMissingImageInfo
    }
    
    sbom, err := s.sbomCreator.CreateSBOM(ctx, image)
    if err != nil {
        return nil, fmt.Errorf("creating SBOM: %w", err)
    }
    
    return s.cveScanner.ScanSBOM(ctx, sbom)
}
```

### Adding New Features

1. Define types in `core/domain/`
2. Define interface in `core/ports/`
3. Implement logic in `core/services/`
4. Implement adapter in `adapters/v1/`
5. Add HTTP handler in `controllers/`
6. Wire up in `cmd/http/main.go`
7. Add tests for each layer

---

## Testing Requirements

### Minimum Coverage

| Package | Target |
|---------|--------|
| `core/services/` | 80% |
| `core/domain/` | 90% |
| `controllers/` | 70% |
| `adapters/v1/` | 60% |

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test -v ./core/services/...
```

### Writing Tests

Use table-driven tests:

```go
func TestScanService_ValidateImage(t *testing.T) {
    tests := []struct {
        name    string
        image   string
        wantErr error
    }{
        {
            name:    "valid image",
            image:   "nginx:latest",
            wantErr: nil,
        },
        {
            name:    "empty image",
            image:   "",
            wantErr: domain.ErrMissingImageInfo,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := service.ValidateImage(tt.image)
            assert.Equal(t, tt.wantErr, err)
        })
    }
}
```

---

## Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and ideas
- **Slack** - [#kubescape](https://cloud-native.slack.com/archives/C04EY3ZF9GE) on CNCF Slack

### Issue Guidelines

**Bug Reports:**
- Go version (`go version`)
- Kubevuln version
- Steps to reproduce
- Expected vs actual behavior
- Logs (if applicable)

**Feature Requests:**
- Use case description
- Proposed solution
- Alternatives considered

---

## Recognition

Contributors are recognized in:
- Release notes
- [MAINTAINERS.md](https://github.com/kubescape/project-governance/blob/main/MAINTAINERS.md)
- GitHub contributors list

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

Thank you for contributing to Kubevuln! 🎉