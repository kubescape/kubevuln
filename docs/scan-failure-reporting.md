# Scan Failure Reporting

When kubevuln cannot complete a vulnerability scan for an image, it emits a **structured scan
failure report** to the backend so the platform can surface the failure to the user (instead of
the failure being silent). Reporting is best-effort and never changes the scan's own control flow.

## When a report is sent

A report is sent from each scan entry point after the operation's existing retries are exhausted:

- `GenerateSBOM()` — SBOM could not be created (unsupported image, image too large, auth/pull
  failure, timeout), including a created SBOM whose status comes back `Incomplete`/`TooLarge`.
  This last case used to be missed: `GenerateSBOM` stored the degraded SBOM and returned success
  regardless of status, the one entry point that didn't check for it. It now checks and reports
  the failure the same way the other three do.
- `ScanCVE()` — an SBOM exists but CVE matching failed.
- `ScanCP()` — continuous-protection scan failures (may cover several images per scan).
- `ScanRegistry()` — registry image scan failures (reported at image level, no workload context).

Reporting is **fire-and-forget**: a failure to send the report is logged and does not fail or
retry the scan.

## Failure classification

kubevuln maps the underlying error to a stable **failure case** and a short **reason code**
(defined in [`armoapi-go/scanfailure`](https://github.com/armosec/armoapi-go)) rather than
sending raw error strings. Classification helpers (`classifySBOMError`, `classifySBOMStatus`)
detect, for example, image auth failures (`errors.As(*transport.Error)`), `MANIFEST_UNKNOWN`,
`TooLarge` / `Incomplete` SBOM statuses, and requested-but-unavailable image platforms
(`errors.As(*image.ErrPlatformMismatch)`, or its rendered "mismatched platform" text for scans
routed through the sidecar, which loses the typed error crossing gRPC). armoapi-go has no
dedicated "platform not found" code, so this maps to the closest existing one,
`ReasonImageNotFound` — distinguishing it from the generic `ReasonSBOMGenerationFailed`
fallback it used to fall into. The raw error is preserved in a separate `Error` field for
backend debugging; the reason code drives the user-facing text (mapped downstream).

Failure cases: CVE scan failure, SBOM generation failure, OOM kill, backend post failure.

The same reason code also lands on the HTTP controller's Prometheus metrics: the scan services
create the `*domain.ScanError` at the point of failure — the same call site that already
computes the reason for `ReportScanFailure` above — and `recordScan` (`controllers/http.go`)
reads it back off the error the controller receives, attaching it as a `reason` attribute on
`kubevuln_scans_completed_total` and
`kubevuln_scan_duration_seconds` (see [API.md](API.md#metrics)). This gives an operator with
only `/metrics` access (no backend `ReportScanFailure` stream, no pod logs) the same
distinction between failure causes that this document describes, instead of a single opaque
`outcome="error"` bucket.

## Report shape

`ScanFailureReport` (from `armoapi-go/scanfailure`) carries the customer GUID, image tag/hash,
the failure case + reason code, timestamp, optional job/registry fields, and a per-workload list
(`clusterName`, `namespace`, `workloadKind`, `workloadName`, `containerName`) for in-cluster
scans. It is delivered via the `Platform` port (`ReportScanFailure`) implemented by the backend
adapter, which POSTs to the backend report endpoint.

## OOM resilience — SBOM scanner sidecar

SBOM generation (Syft) is the most memory-intensive step and can be OOM-killed on large images.
To keep an OOM kill from taking down the main kubevuln process, SBOM generation can run in a
dedicated **sidecar** container (gRPC over a Unix domain socket). The main process detects a
crashed/unavailable sidecar and surfaces it as a scan failure (enabling OOM-kill reporting),
then continues serving. The sidecar is opt-in via the `SBOM_SCANNER_SOCKET` environment variable;
when unset, kubevuln uses the in-process Syft adapter as before.

## Testing

Unit tests cover the reporting adapter and the classifier (`TestBackendAdapter_ReportScanFailure`,
`TestClassify*`). End-to-end coverage (a real scan failure producing a user notification) lives in
the platform system tests.
