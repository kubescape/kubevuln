# Subprocess SBOM Creation

## Problem

When kubevuln scans large container images, the Syft SBOM generation step can consume
unbounded memory. If the Go runtime or the kernel OOM-killer terminates the process,
the entire kubevuln pod crashes — losing all in-flight scans and requiring a restart.

## Solution

`SubprocessSBOMCreator` isolates SBOM generation in a **child process**. The parent
(kubevuln main process) survives even if the child is OOM-killed, and reports a
structured error instead of crashing.

## How It Works

```
┌───────────────────────────────────────────────────────┐
│  kubevuln (parent)                                    │
│                                                       │
│  1. Serialize scan request as JSON                    │
│  2. Re-exec self with KUBEVULN_SBOM_WORKER=1          │
│  3. Send request via os.Pipe (FD 3), read FD 4        │
│  4. If child is SIGKILL'd → ErrChildOOMKilled         │
│  5. If child times out   → ErrChildTimeout            │
│  6. If child succeeds    → return SBOM                │
└──────────────┬────────────────────────────────────────┘
               │ fork/exec
┌──────────────▼────────────────────────────────────────┐
│  kubevuln (child worker)                              │
│                                                       │
│  1. Apply RLIMIT_AS memory limit (if set)             │
│  2. Read request from pipe FD 3                       │
│  3. Create SyftAdapter, run CreateSBOM()              │
│  4. Write JSON response to pipe FD 4                  │
│  5. Exit — stdout/stderr free for normal logging      │
└───────────────────────────────────────────────────────┘
```

### Key design decisions

- **Self-re-exec**: The child runs the same kubevuln binary with env var
  `KUBEVULN_SBOM_WORKER=1`. This is checked at the top of `main()` before any
  HTTP server setup.
- **os.Pipe for IPC (not stdin/stdout)**: The parent creates two pipes and passes
  them as `ExtraFiles` (FD 3 = request, FD 4 = response). This keeps stdout/stderr
  free for normal logging in the child. If Syft or any dependency logs to stdout,
  it won't corrupt the JSON data channel.
- **Memory limit**: The parent passes `KUBEVULN_SBOM_WORKER_MEMLIMIT` (bytes) to
  the child, which applies it via `RLIMIT_AS`. When hit, memory allocations fail
  and the process crashes — the parent detects SIGKILL and returns `ErrChildOOMKilled`.
- **Timeout buffer**: The parent's context timeout = child scan timeout + 30s, so
  the child can return a clean timeout error before the parent force-kills it.
- **Temp cleanup**: After a child failure, the parent removes orphaned `stereoscope*`
  temp directories that the killed child left behind.

## When It Activates

The feature is **off by default**. It activates when both conditions are true:

1. Config field `subprocessSBOM` is set to `true`
2. kubevuln receives an SBOM creation request (via `/v1/generateSBOM` endpoint)

When disabled, `SubprocessSBOMCreator` delegates directly to `SyftAdapter` with
zero overhead — it's a transparent wrapper.

## Configuration

Set these in the kubevuln ConfigMap (`clusterData.json`) or via environment variables:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subprocessSBOM` | bool | `false` | Enable subprocess SBOM creation |
| `subprocessSBOMMemoryLimit` | int64 | `0` | Child process memory limit in bytes. `0` = no limit. Example: `2147483648` (2 GiB) |
| `scanTimeout` | duration | `5m` | Scan timeout (applies to both parent and child) |

## Error Sentinel Values

Callers can check for specific failure modes:

| Error | Meaning |
|-------|---------|
| `ErrChildOOMKilled` | Child received SIGKILL (typically OOM) |
| `ErrChildSignaled` | Child killed by another signal |
| `ErrChildTimeout` | Child exceeded scan timeout |

These are used downstream to classify scan failures for the vulnerability scan
failure notification pipeline (SUB-7074).

## Files

| File | Purpose |
|------|---------|
| `subprocess_sbom.go` | Parent-side orchestration + child worker entry point |
| `subprocess_sbom_test.go` | Unit tests for JSON roundtrip, delegation, timeout |
| `../../cmd/http/main.go` | Worker mode detection (`KUBEVULN_SBOM_WORKER=1` check) |
| `../../config/config.go` | Config fields and defaults |
