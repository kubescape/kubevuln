# SecurityException CRD — Design Document

## Background & Problem Statement

Kubescape currently has **no in-cluster, declarative exception mechanism**. All vulnerability exceptions come from the Armo cloud API (`BackendAdapter.GetCVEExceptions()` in kubevuln), and posture exceptions come from JSON files or cloud API (`IExceptionsGetter` in kubescape). This means:

- **No GitOps-native workflow** — exceptions don't live alongside app code
- **Cloud dependency** — users without an external backend (like ARMO) and air-gapped clusters can't use exceptions
- **No audit trail** via Git history
- **CI and runtime scanning** have different exception mechanisms

## Solution

Introduce a **SecurityException CRD** (`kubescape.io/v1`) that teams deploy via GitOps alongside their applications. It covers both vulnerability exceptions (OpenVEX-compatible) and posture/compliance exceptions in a single resource.

## CRD Specification

### API Group & Versioning

| Field | Value |
|-------|-------|
| Group | `kubescape.io` |
| Version | `v1` |
| Kinds | `SecurityException` (namespaced), `ClusterSecurityException` (cluster-scoped) |
| Short names | `se`, `cse` |

### Workload Matching

SecurityException uses standard Kubernetes matching patterns to determine which workloads an exception applies to. Matching is defined at the top-level `spec.match` field and applies to all vulnerability and posture entries within the resource.

#### Match fields

| Field | Type | Description |
|-------|------|-------------|
| `namespaceSelector` | `metav1.LabelSelector` | Selects namespaces by label. Standard K8s label selector supporting `matchLabels` and `matchExpressions`. Only meaningful on `ClusterSecurityException`. |
| `objectSelector` | `metav1.LabelSelector` | Selects workloads by their labels. Standard K8s label selector. |
| `resources` | `[]ResourceMatch` | Explicit list of workloads by kind/name. |
| `images` | `[]string` | Glob patterns matched against container image references (see "Image Matching" below). Applies only to vulnerability entries (posture controls are about workload configuration, not image contents). |

`ResourceMatch` fields:

| Field | Type | Description |
|-------|------|-------------|
| `apiGroup` | `string` | API group (e.g., `apps`, empty string for core). Optional — defaults to all groups. |
| `kind` | `string` | Resource kind (e.g., `Deployment`, `StatefulSet`). Required. |
| `name` | `string` | Exact resource name. Optional — omit to match all of this kind. |

#### Matching semantics

- **`namespaceSelector` AND `objectSelector` AND `resources` AND `images`**: all specified selectors must match (standard K8s convention, consistent with ValidatingWebhookConfiguration)
- **Within `resources` list**: OR — any entry can match
- **Within `images` list**: OR — any pattern can match
- **Within `matchExpressions`**: AND (standard K8s `LabelSelector` behavior)
- **Omitted selectors**: match everything (e.g., no `objectSelector` = all workloads). Only specified selectors constrain the match.
- **`images`**: only applies to vulnerability entries. Ignored for posture entries.
- **Namespaced `SecurityException`**: implicitly scoped to its own namespace; `namespaceSelector` is not available
- **Cluster-scoped `ClusterSecurityException`**: uses `namespaceSelector` to target namespaces

#### Image Matching

Image patterns in `match.images` use Go's `path.Match` glob syntax:

- `*` matches any sequence of characters **except** `/` (path separators)
- `?` matches any single character except `/`
- `**` is **not** supported — use multiple patterns instead
- Character classes like `[abc]` are supported

Patterns are matched against the **fully qualified, normalized** image reference. The scanner normalizes images before matching:
- `nginx` → `docker.io/library/nginx:latest`
- `nginx:1.25` → `docker.io/library/nginx:1.25`
- `my-registry.io/app:v1` → `my-registry.io/app:v1` (already qualified)

This means patterns should always be written against the full form:
- `docker.io/library/nginx:*` — matches any nginx tag
- `my-registry.io/team/*:*` — matches any image under `my-registry.io/team/` (one level deep)
- `docker.io/library/nginx:1.25` — matches exact image reference

### Full YAML Examples

#### Namespaced — target specific workloads by label and name

```yaml
apiVersion: kubescape.io/v1
kind: SecurityException
metadata:
  name: nginx-exceptions
  namespace: production
spec:
  author: "team-platform@example.com"
  reason: "Accepted risks for Q2 2026 release"
  expiresAt: "2026-07-01T00:00:00Z"

  match:
    objectSelector:
      matchLabels:
        app: nginx
    resources:
      - kind: Deployment
        name: nginx-frontend

  vulnerabilities:
    - vulnerability:
        id: "CVE-2021-44228"
        aliases: ["GHSA-jfh8-c2jp-5v3q"]
      status: "not_affected"
      justification: "component_not_present"
      impactStatement: "No Java runtime in this container"
      expiredOnFix: true

    - vulnerability:
        id: "CVE-2023-44487"
      status: "not_affected"
      justification: "inline_mitigations_already_exist"
      impactStatement: "WAF mitigates HTTP/2 rapid reset"

  posture:
    - controlID: "C-0034"
      frameworkName: "NSA"
      action: "alert_only"
```

#### Namespaced — apply to all workloads in namespace (no match selector)

```yaml
apiVersion: kubescape.io/v1
kind: SecurityException
metadata:
  name: namespace-wide-log4j
  namespace: production
spec:
  reason: "Log4j not exploitable — no Java in any container"

  vulnerabilities:
    - vulnerability:
        id: "CVE-2021-44228"
      status: "not_affected"
      justification: "component_not_present"
```

#### Cluster-scoped — target namespaces by label

```yaml
apiVersion: kubescape.io/v1
kind: ClusterSecurityException
metadata:
  name: staging-relaxed-posture
spec:
  author: "platform-team@example.com"
  reason: "Relaxed posture checks for non-production"

  match:
    namespaceSelector:
      matchLabels:
        env: staging

  posture:
    - controlID: "C-0034"
      action: "ignore"
    - controlID: "C-0017"
      action: "alert_only"
```

#### Cluster-scoped — target by image pattern

```yaml
apiVersion: kubescape.io/v1
kind: ClusterSecurityException
metadata:
  name: nginx-http2-exception
spec:
  reason: "HTTP/2 rapid reset mitigated by WAF for all nginx images"

  match:
    images:
      - "docker.io/library/nginx:*"
      - "my-registry.io/custom-nginx:*"

  vulnerabilities:
    - vulnerability:
        id: "CVE-2023-44487"
      status: "not_affected"
      justification: "inline_mitigations_already_exist"
      impactStatement: "WAF mitigates HTTP/2 rapid reset"
```

#### Cluster-scoped — target specific workloads across namespaces

```yaml
apiVersion: kubescape.io/v1
kind: ClusterSecurityException
metadata:
  name: infra-daemonset-exceptions
spec:
  reason: "Known CVEs in infrastructure DaemonSets, tracked in JIRA-1234"

  match:
    namespaceSelector:
      matchExpressions:
        - key: env
          operator: In
          values: ["production", "staging"]
    resources:
      - kind: DaemonSet
        name: node-exporter
      - kind: DaemonSet
        name: fluent-bit

  vulnerabilities:
    - vulnerability:
        id: "CVE-2023-44487"
      status: "not_affected"
      justification: "inline_mitigations_already_exist"
      expiredOnFix: true
```

### VEX Status/Justification Enums

Following the OpenVEX standard:

- **status**: `not_affected`, `fixed`, `under_investigation`
- **justification** (when `not_affected`): `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`

### `expiredOnFix` Behavior

When `expiredOnFix: true` is set on a vulnerability entry, the exception is automatically ignored when a fix is available for the vulnerability. This is evaluated at scan time using the scan result data — no external database lookup is needed. Grype's scan output already includes fix availability for each CVE. During exception matching in kubevuln (`getCVEExceptionMatchCVENameFromList`), if the scan result indicates a fix exists and the exception has `expiredOnFix: true`, the exception is skipped and the vulnerability is reported as usual.

This means:
- The exception remains in the CRD (it is not deleted or mutated)
- The `status.conditions` should reflect that the exception was skipped due to fix availability
- If the fix is later retracted (e.g., image reverted to an older version), the exception automatically applies again on the next scan

### Posture Action Enums

- **`ignore`** — the control finding is removed from results and compliance scoring entirely. It is not counted as a pass or fail. Use for controls that are not applicable to the workload.
- **`alert_only`** — the control still **fails** in compliance scoring, but is annotated as acknowledged/excepted in the report. The compliance score reflects the real security state; the annotation signals the failure is known and accepted. Use for controls that genuinely fail but the risk is accepted.

## Architecture

### Component Interaction

```
┌─────────────┐   Watch    ┌──────────┐   Rescan    ┌──────────┐
│  GitOps /   │──────────→ │ Operator │───────────→ │ kubevuln │
│  kubectl    │            │ Watcher  │             │          │
└─────────────┘            └──────────┘             └──────────┘
      │                         │                        │
      │ apply CRD               │ rescan trigger         │ read CRDs
      ▼                         │                        ▼
┌─────────────┐                 │              ┌──────────────────┐
│  API Server │◄────────────────┘              │ SecurityException│
│  (CRD)      │◄───────────────────────────────│ Adapter          │
└─────────────┘                                └──────────────────┘
                                                        │
                                                        ▼ convert
                                               ┌──────────────────┐
                                               │ Existing          │
                                               │ Exception Flow    │
                                               │ (armotypes)       │
                                               └──────────────────┘
```

### Integration Design

#### kubevuln — Vulnerability Exception Path

1. New `SecurityExceptionProvider` interface in `core/ports/providers.go`
2. New `APIServerSecurityExceptionAdapter` using dynamic K8s client
3. `BackendAdapter.GetCVEExceptions()` merges CRD exceptions with cloud exceptions
4. Conversion: `SecurityException → armotypes.VulnerabilityExceptionPolicy`

The key insight is that by converting CRD data into existing `armotypes.VulnerabilityExceptionPolicy` format, the entire downstream flow (`getCVEExceptionMatchCVENameFromList`, `ExceptionApplied` marking, `Summarize()` excluded stats) works unchanged.

**Match conversion**: `spec.match` fields are converted to `PortalDesignator` attributes:
- `resources[].kind` → `scope.kind`
- `resources[].name` → `scope.name`
- `objectSelector` / `namespaceSelector` → evaluated at fetch time to resolve matching workloads, then individual designators are created per workload

#### kubescape — Posture Exception Path

1. New `CRDExceptionsGetter` implementing `IExceptionsGetter`
2. Wraps existing getter, merges CRD posture entries with inner getter results
3. Conversion: `SecurityException → armotypes.PostureExceptionPolicy`
4. Wired into `getExceptionsGetter()` in `initutils.go`

**Match conversion**: `spec.match` fields are converted to `PostureExceptionPolicy.Resources` (array of `PortalDesignator`):
- `resources[].kind` → `PortalDesignator.Attributes["kind"]`
- `resources[].name` → `PortalDesignator.Attributes["name"]`
- `namespaceSelector` → resolved to namespace list → `PortalDesignator.Attributes["namespace"]`

#### operator — Watch & Rescan

1. New `SecurityExceptionWatchHandler` watching both `securityexceptions` and `clustersecurityexceptions`
2. Uses `CooldownQueue` to debounce rapid changes
3. On change: determines affected namespaces/workloads, dispatches rescan commands
4. Expiry controller: goroutine checking every 5 minutes for expired CRDs

## Identifier Bridging

Vulnerability exceptions are matched by **CVE ID** (`vulnerability.id`) and optionally scoped to specific images via `match.images` glob patterns. This covers the common use cases of excepting a known CVE globally or within specific images.

**Future extension — `products` (purl-based package matching)**: A future version may add OpenVEX-style `products` fields using Package URLs (purls) for fine-grained matching at the package level inside an SBOM (e.g., `pkg:deb/debian/openssl@1.1.1`). This is deferred from v1 as CVE ID + image pattern matching is sufficient for most use cases, and purl matching adds significant complexity (purl parsing, SBOM correlation, version range matching).

## Authorization & Validation

### RBAC Guidance

SecurityException CRDs suppress security findings — access should be restricted to trusted roles. Recommended RBAC setup:

| Role | `SecurityException` | `ClusterSecurityException` |
|------|--------------------|-----------------------------|
| Security team / platform admins | `create`, `update`, `delete`, `get`, `list`, `watch` | `create`, `update`, `delete`, `get`, `list`, `watch` |
| Development teams | `get`, `list`, `watch` (read-only) | `get`, `list`, `watch` (read-only) |
| Scanner components (kubevuln, kubescape) | `get`, `list`, `watch` | `get`, `list`, `watch` |
| Operator | `get`, `list`, `watch` | `get`, `list`, `watch` |

Scanner components also need `create` and `patch` on `events` (core API group) to emit Kubernetes Events bound to SecurityException resources.

Organizations should create dedicated `ClusterRole`/`Role` resources for SecurityException management rather than granting access through broad wildcard rules.

**Note on cluster-wide exceptions**: A `ClusterSecurityException` with no match selectors will apply to all workloads in all namespaces. This is by design — it enables legitimate use cases like "this CVE is not exploitable anywhere in our cluster." RBAC is the appropriate control to prevent unintended broad exceptions; restrict `create`/`update` on `ClusterSecurityException` to trusted roles.

### CRD Validation Rules (CEL)

The CRD schema should include CEL validation rules to enforce invariants at admission time, without requiring a separate webhook:

- `justification` is required when `status` is `not_affected`
- `expiresAt`, if set, must be a valid RFC3339 timestamp in the future (at creation time)
- At least one entry must exist in either `vulnerabilities` or `posture`
- `posture[].action` must be one of `ignore`, `alert_only`
- `vulnerabilities[].status` must be one of `not_affected`, `fixed`, `under_investigation`

## Conflict Resolution & Precedence

When both cloud-based exceptions (ARMO backend) and CRD-based exceptions exist for the same CVE/control on the same workload:

- **Cloud exceptions take precedence.** If the cloud backend has an exception for a given CVE on a workload, the cloud exception's status and metadata are used, and any conflicting CRD exception for the same CVE on the same workload is ignored.
- **Non-overlapping exceptions are merged.** CRD exceptions for CVEs/controls not covered by cloud exceptions are applied normally. Cloud exceptions for CVEs/controls not in any CRD are also applied normally.
- **Implementation**: During the merge in `GetCVEExceptions()`, cloud exceptions are added first. CRD exceptions are only appended for CVE+workload combinations not already covered by a cloud exception.

This ensures the cloud backend remains the authoritative source when both are in use, while CRD exceptions extend coverage for cases the cloud does not address.

## Migration Path

Cloud-based exceptions and CRD-based exceptions work simultaneously. Organizations can gradually migrate:

1. Deploy SecurityException CRDs for new exceptions
2. Existing cloud exceptions continue to work (and take precedence on overlap)
3. Remove cloud exceptions as CRD equivalents are confirmed working

## Observability

SecurityException CRDs do not use the status subresource. Observability is provided through **Kubernetes Events** emitted by the scanners.

### Events

When a scanner evaluates exceptions during a scan, it emits Events on the SecurityException/ClusterSecurityException resource that was matched:

- **kubevuln**: Emits an Event when a vulnerability exception matches during a scan (e.g., "Matched CVE-2021-44228 on Deployment/nginx-frontend in namespace production")
- **kubescape**: Emits an Event when a posture exception matches during a scan (e.g., "Matched control C-0034 on Deployment/nginx-frontend")

Users can inspect exception activity via `kubectl describe securityexception <name>` and see recent Events. Events are automatically garbage-collected by Kubernetes.

### Expiry

Expiry (`expiresAt`) is evaluated at scan time by the scanners — no controller or status update is needed. When a scanner reads a SecurityException and `expiresAt` is in the past, the exception is simply skipped. This means:

- No component writes to the SecurityException status subresource
- Expired exceptions remain in the cluster until explicitly deleted by the user
- The next scan after expiry will report previously-excepted findings as normal

### Audit Trail

The primary audit trail for SecurityException changes is **Git history** when using a GitOps workflow (Flux, ArgoCD). For in-cluster mutations (e.g., direct `kubectl edit`), Kubernetes API server audit logging captures all changes including the user, timestamp, and diff. Organizations requiring audit compliance should ensure K8s audit logging is enabled and configured to capture `kubescape.io` resource mutations.

## OpenVEX Compatibility

The vulnerability exception entries align with OpenVEX statements:

- `vulnerability.id` → VEX vulnerability ID
- `status` → VEX status
- `justification` → VEX justification
- `impactStatement` → VEX impact statement

Note: OpenVEX `products` (purl-based product/subcomponent matching) is deferred to a future version. See "Identifier Bridging" above.
