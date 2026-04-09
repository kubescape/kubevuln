# SecurityException CRD — Design Review

**Design document**: [security-exception-design.md](security-exception-design.md)
**Date**: 2026-04-09

---

## Summary

The core model — CRD-to-armotypes bridge, dual-scope kinds (namespaced + cluster), and OpenVEX alignment — is sound. The major gaps are in the **security and operational boundary**: authorization, blast radius control, conflict semantics, and observability. For a feature that suppresses security findings, these are table stakes, not nice-to-haves.

---

## Major Review Points

### 1. No Authorization / Admission Control Story — ADDRESSED

The design has no discussion of **who is allowed to create exceptions** and how to prevent abuse. A malicious or careless actor with RBAC access to the CRD could suppress all vulnerability findings cluster-wide. The design needs:

- A validating admission webhook (or CEL validation rules) to enforce invariants (e.g., `expiresAt` must be in the future, `justification` is required when `status: not_affected`)
- Guidance on RBAC lockdown — which roles should get `create`/`update` on these CRDs
- Consideration of an approval workflow or annotation (e.g., `approved-by`) for high-blast-radius exceptions

> **Resolution**: Added "Authorization & Validation" section to design doc with RBAC guidance table (security team full access, developers read-only) and CEL validation rules (justification required for `not_affected`, future `expiresAt`, enum validation). Approval workflow deferred as out of scope for v1.

### 2. `expiredOnFix` Is Undefined and Has Deep Implications — ADDRESSED

The field appears in examples but is **never specified** in the schema section. This is a significant feature that requires its own design:

- How does the system determine a fix is available? Grype feed? Image rescan?
- What is the lifecycle — does it flip a status condition? Delete the entry? Trigger a notification?
- This effectively requires continuous reconciliation against vulnerability databases, which is a different operational model than the rest of the CRD

> **Resolution**: Added "`expiredOnFix` Behavior" section to design doc. No external DB access needed — fix availability comes from Grype's scan output, which is already present at exception matching time. kubevuln's `getCVEExceptionMatchCVENameFromList` already supports this via the `filterFixed` parameter. The CRD is not mutated; the exception is simply skipped when a fix is detected, and reapplies if the fix is retracted.

### 3. `products` Field Is Described but Never Specified — ADDRESSED

The "Identifier Bridging" section describes purl-based product matching, but `products` never appears in the CRD spec table or the YAML examples. Either spec it fully (type, validation, matching semantics) or cut it from v1alpha1 and add it later. Half-specified fields in a CRD are a compatibility hazard.

> **Resolution**: Cut `products` from v1. CVE ID + `match.images` glob patterns cover the common use cases. Purl-based package-level matching is noted as a future extension in the "Identifier Bridging" and "OpenVEX Compatibility" sections.

### 4. Conflict Resolution and Precedence Are Undefined — ADDRESSED

The migration section says cloud and CRD exceptions "work simultaneously" but does not define:

- What happens when a CRD says `not_affected` and the cloud says `under_investigation` for the same CVE on the same workload?
- Is the merge union (most permissive wins) or does one source take precedence?
- This matters for compliance audits — you need deterministic, documentable behavior

> **Resolution**: Added "Conflict Resolution & Precedence" section. Cloud exceptions take precedence on overlap — if both sources define an exception for the same CVE on the same workload, the cloud exception wins. Non-overlapping exceptions from both sources are merged normally.

### 5. Unbounded Blast Radius on Cluster-Scoped Exceptions — ADDRESSED

A `ClusterSecurityException` with **no `namespaceSelector`** and **no `resources`** matches every workload in every namespace, including `kube-system`. The design should:

- Require at least one non-empty match constraint, or explicitly document and warn about "match-all" exceptions
- Consider a `maxScope` safety net or annotation that forces the author to acknowledge cluster-wide intent
- The `CooldownQueue` debounce is not sufficient — a single broad CRD change could trigger rescans across every namespace

> **Resolution**: This is by design — cluster-wide exceptions without match constraints are a valid use case (e.g., "this CVE is not exploitable anywhere"). Added a note in the RBAC section explicitly documenting this behavior and pointing to RBAC as the appropriate control. No schema constraints added — consistent with how other cluster-scoped K8s resources (e.g., ClusterRole) handle broad access.

### 6. Status Subresource Is Underspecified — ADDRESSED

The example shows `status.matchedVulnerabilities`, `status.conditions`, etc., but there is no spec for:

- Which controller owns the status (kubevuln? operator? both?)
- Update frequency and what triggers a status refresh
- What the conditions represent (e.g., `Expired`, `MatchError`, `Applied`)
- Status is the primary observability surface — operators will build alerts on it

> **Resolution**: Status subresource is not used. Observability is provided through Kubernetes Events emitted by the scanners (kubevuln/kubescape) when exceptions match during scans. Expiry is evaluated at scan time — no controller writes to status. Removed status block from YAML examples. This keeps the operator as a pure trigger mechanism and avoids controller ownership conflicts.

### 7. Posture `action` Semantics Need Compliance Scoring Definition — ADDRESSED

`alert_only` says "keep the finding but mark as acknowledged" — but does the control still **fail** in compliance scoring? If a framework requires C-0034 to pass and you set `alert_only`, does the cluster report as compliant or not? This distinction is critical for regulatory use cases (SOC2, PCI-DSS). `ignore` vs `alert_only` must be defined in terms of their effect on `ComplianceScore` and `ResourceResult.Status`.

> **Resolution**: Defined explicitly in design doc. `ignore` removes the finding from results and compliance scoring entirely (not counted as pass or fail). `alert_only` keeps the control as a **failure** in compliance scoring but annotates it as acknowledged — the compliance score reflects reality, the annotation signals accepted risk.

### 8. No Audit Trail Beyond Git — ADDRESSED

The document cites Git history as the audit mechanism, but in-cluster mutations (direct `kubectl edit`, controller reconciliation) bypass Git. Consider:

- An audit annotation recording the last human modifier
- Integration with Kubernetes audit logging guidance
- Whether the CRD should have an immutable phase after creation (update-only via delete+recreate)

> **Resolution**: Added "Audit Trail" note in the Observability section. Git history is the primary audit mechanism for GitOps workflows. For in-cluster mutations, Kubernetes API server audit logging already captures all changes. No custom audit annotations or immutability constraints needed.

### 9. Image Glob Matching Is Underspecified and Risky — ADDRESSED

`images: ["docker.io/library/nginx:*"]` — what matching library is used? Does `*` match path separators? Is `**` supported? Does it match the normalized or raw image reference? (`nginx:latest` vs `docker.io/library/nginx:latest` are the same image). Ambiguous glob semantics in a security-suppression context is a vulnerability — an overly broad pattern could silently suppress findings for unintended images.

> **Resolution**: Added "Image Matching" section to design doc. Uses Go's `path.Match` — `*` does not match `/` (prevents accidental over-matching), `**` is not supported, patterns match against the fully qualified normalized image reference (e.g., `nginx` is normalized to `docker.io/library/nginx:latest` before matching). Includes examples of correct pattern usage.

### 10. Missing: Observability and Dry-Run Mode — PARTIALLY ADDRESSED

There is no way for a user to **preview** what an exception would match before applying it. For a security-critical CRD, this is a significant operational gap. Consider:

- A `dryRun: true` field or a status endpoint that shows matched workloads without suppressing findings
- Events emitted when an exception matches (or stops matching) a workload
- Metrics (Prometheus) for number of active exceptions, matched findings, expired exceptions

> **Resolution**: Events are covered — scanners emit Kubernetes Events on SecurityException resources when exceptions match during scans (see point 6). Dry-run preview and Prometheus metrics are deferred as future enhancements. Users can validate CRD schema via `kubectl apply --dry-run=server` and observe matching behavior through Events after the next scan.
