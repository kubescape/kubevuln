# Subprocess SBOM Creation

## Problem

When kubevuln scans large container images, the Syft SBOM generation step can consume
unbounded memory. If the Go runtime or the kernel OOM-killer terminates the process,
the entire kubevuln pod crashes — losing all in-flight scans and requiring a restart.

## Solution

`SubprocessSBOMCreator` isolates SBOM generation in a **child process** using
[moby/sys/reexec](https://pkg.go.dev/github.com/moby/sys/reexec). The parent
(kubevuln main process) survives even if the child is OOM-killed, and reports a
structured error instead of crashing.

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  kubevuln (parent)                                  │
│                                                     │
│  1. Serialize scan request as JSON                  │
│  2. reexec.Command("sbom-worker") — re-exec self    │
│  3. Send request via os.Pipe (FD 3), read FD 4      │
│  4. If child is SIGKILL'd → ErrChildOOMKilled       │
│  5. If child times out   → ErrChildTimeout          │
│  6. If child succeeds    → return SBOM              │
│  7. On SIGTERM           → forward to all children  │
└──────────────┬──────────────────────────────────────┘
               │ reexec (argv[0] = "sbom-worker")
┌──────────────▼──────────────────────────────────────┐
│  kubevuln (child worker)                            │
│                                                     │
│  1. reexec.Init() matches "sbom-worker" handler     │
│  2. Apply RLIMIT_AS memory limit (if set)           │
│  3. Read request from pipe FD 3                     │
│  4. Create SyftAdapter, run CreateSBOM()            │
│  5. Write JSON response to pipe FD 4                │
│  6. Exit — stdout/stderr free for normal logging    │
└─────────────────────────────────────────────────────┘
```

### Key design decisions

- **moby/sys/reexec**: Uses the `init()` + `reexec.Register("sbom-worker", fn)`
  pattern (same as Docker). `reexec.Init()` is called at the top of `main()` —
  if the binary was re-exec'd as a registered handler, it runs and returns true.
  No env var checks polluting `main()`.

- **os.Pipe for IPC (not stdin/stdout)**: The parent creates two pipes and passes
  them as `ExtraFiles` (FD 3 = request, FD 4 = response). This keeps stdout/stderr
  free for normal logging in the child. If Syft or any dependency logs to stdout,
  it won't corrupt the JSON data channel.

- **Memory limit**: The parent passes `KUBEVULN_SBOM_WORKER_MEMLIMIT` (bytes) to
  the child, which applies it via `RLIMIT_AS`. When hit, memory allocations fail
  and the process crashes — the parent detects SIGKILL and returns `ErrChildOOMKilled`.

- **Timeout buffer**: The parent's context timeout = child scan timeout + 30s, so
  the child can return a clean timeout error before the parent force-kills it.

- **SIGTERM propagation**: `SubprocessSBOMCreator.Shutdown()` sends SIGTERM to all
  tracked child processes. This is called during kubevuln's graceful shutdown so
  children don't become orphans.

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
| `subprocess_sbom.go` | Parent-side orchestration + child worker handler |
| `subprocess_sbom_test.go` | Unit + integration tests (OOM simulation, parent survival) |
| `../../cmd/http/main.go` | `InitReexec()` call at top of main() |
| `../../config/config.go` | Config fields and defaults |
