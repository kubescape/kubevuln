# Scan Failure Reporting

When kubevuln cannot complete a vulnerability scan for an image, it emits a **structured scan
failure report** to the backend so the platform can surface the failure to the user (instead of
the failure being silent). Reporting is best-effort and never changes the scan's own control flow.

## When a report is sent

A report is sent from each scan entry point after the operation's existing retries are exhausted:

- `GenerateSBOM()` — SBOM could not be created (unsupported image, image too large, auth/pull
  failure, timeout).
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
and `TooLarge` / `Incomplete` SBOM statuses. The raw error is preserved in a separate `Error`
field for backend debugging; the reason code drives the user-facing text (mapped downstream).

Failure cases: CVE scan failure, SBOM generation failure, OOM kill, backend post failure.

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
