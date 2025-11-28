# Security Policy

This document outlines security procedures and policies for the Kubevuln project.

---

## Table of Contents

- [Centralized Security Policy](#centralized-security-policy)
- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Considerations](#security-considerations)
- [Security Best Practices](#security-best-practices)

---

## Centralized Security Policy

Kubevuln follows the Kubescape project's centralized security policy.

**👉 [View the centralized SECURITY.md](https://github.com/kubescape/project-governance/blob/main/SECURITY.md)**

---

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Latest  | ✅ Yes             |
| < 1 year old | ✅ Yes        |
| > 1 year old | ❌ No         |

We recommend always running the latest version of Kubevuln to ensure you have the most recent security patches.

---

## Reporting a Vulnerability

### DO NOT report security vulnerabilities through public GitHub issues.

### Preferred Method

Report vulnerabilities through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/kubescape/kubevuln/security)
2. Click "Report a vulnerability"
3. Fill out the form with details

### Alternative Method

Email: security@kubescape.io

### What to Include

- Type of vulnerability
- Full path to the affected source file(s)
- Steps to reproduce
- Proof-of-concept (if possible)
- Potential impact

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial response | 48 hours |
| Status update | 7 days |
| Fix timeline estimate | 14 days |
| Public disclosure | After fix is released |

---

## Security Considerations

### Kubevuln-Specific Security

#### Container Registry Access

Kubevuln connects to container registries to pull images for scanning:

- **Credentials**: Registry credentials are passed per-request and are not stored
- **TLS**: Always use TLS when connecting to registries (avoid `useHTTP: true` in production)
- **Least Privilege**: Use read-only registry credentials

#### Vulnerability Database

- The Grype vulnerability database is downloaded from `grype.anchore.io` by default
- For air-gapped environments, use `listingURL` to point to an internal mirror
- Database updates occur every 24 hours

#### Kubernetes RBAC

Kubevuln requires the following Kubernetes permissions when storage is enabled:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubevuln
rules:
  - apiGroups: ["spdx.softwarecomposition.kubescape.io"]
    resources:
      - sbomsyfts
      - vulnerabilitymanifests
      - openvulnerabilityexchangecontainers
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

#### Network Access

| Direction | Target | Purpose | Required |
|-----------|--------|---------|----------|
| Outbound | Container registries | Pull images | Yes |
| Outbound | grype.anchore.io | Vulnerability DB | Yes (unless air-gapped) |
| Outbound | Backend API | Report results | No (use `keepLocal: true`) |
| Inbound | Port 8080 | REST API | Yes |

---

## Security Best Practices

### Deployment

1. **Run as non-root**: The container image runs as non-root by default
2. **Use network policies**: Restrict ingress/egress traffic
3. **Enable TLS**: Use a service mesh or ingress controller with TLS
4. **Resource limits**: Set CPU and memory limits

Example NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubevuln
  namespace: kubescape
spec:
  podSelector:
    matchLabels:
      app: kubevuln
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: kubescape
      ports:
        - port: 8080
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 443  # HTTPS to registries
```

### Configuration

1. **Avoid `keepLocal: false`** with sensitive data unless backend is trusted
2. **Use `skipTLSVerify: false`** (default) in production
3. **Limit `maxImageSize`** to prevent DoS from large images
4. **Set appropriate `scanTimeout`** to prevent resource exhaustion

### Credentials

1. **Never commit credentials** to source control
2. **Use Kubernetes Secrets** for sensitive configuration
3. **Rotate credentials** regularly
4. **Use short-lived tokens** when possible

---

## Security Updates

Security updates are released as patch versions and announced in:

- [GitHub Releases](https://github.com/kubescape/kubevuln/releases)
- [Kubescape Blog](https://kubescape.io/blog/)
- CNCF Slack #kubescape channel

---

## Acknowledgments

We appreciate responsible disclosure from the security community. Contributors who report valid security issues will be acknowledged in release notes (unless they prefer to remain anonymous).

---

## Contact

- **Security Issues**: security@kubescape.io
- **General Questions**: [GitHub Discussions](https://github.com/kubescape/kubevuln/discussions)
- **Slack**: [#kubescape](https://cloud-native.slack.com/archives/C04EY3ZF9GE)