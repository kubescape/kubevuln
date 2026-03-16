# Context: OOM Killer Behavior Fix for kubevuln Subprocess Pattern

## Problem Statement

kubevuln uses an orchestrator/subprocess pattern where the main kubevuln process (PID 1 in the container) spawns child worker processes (e.g., `sbom-worker`). When the container's memory limit is breached, the pod restarts entirely instead of only the offending child process being killed.

### Observed Behavior

- Pod memory limit: 700Mi
- kubevuln (orchestrator): ~130MB RSS
- sbom-worker (child): grows to ~450MB RSS
- Total exceeds 700Mi → OOM → entire pod restarts

### Expected Behavior

The OOM killer should kill only the sbom-worker (highest RSS), while kubevuln survives and can recover (retry, log, spawn a new worker, etc.).

## Root Cause Analysis

The Linux kernel's OOM killer **is** correctly killing only the child process with the highest RSS. The pod restart happens because of a chain reaction:

1. Kernel OOM killer targets the sbom-worker (highest `oom_score` due to highest RSS)
2. sbom-worker is killed with SIGKILL
3. kubevuln (PID 1) either: crashes when it detects the child died, exits because it doesn't handle child death gracefully, or propagates the error and terminates
4. kubelet detects PID 1 has exited → restarts the pod per `restartPolicy`

The cgroup itself is **not** being killed as a whole — the orchestrator is simply not surviving the child's death.

## Required Fix — Two Parts

### Part 1: OOM Score Adjustment (Prioritize Killing Children)

Use `oom_score_adj` to explicitly protect the parent and make children expendable.

**In the orchestrator (kubevuln), on startup:**

```go
// Protect the orchestrator — low OOM score
os.WriteFile("/proc/self/oom_score_adj", []byte("-999"), 0644)
```

**After spawning each child worker:**

```go
// Make the child the preferred OOM target
os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", childPID), []byte("1000"), 0644)
```

Alternatively, the child can set its own score on startup:

```go
// In the child process, early in main()
os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0644)
```

**Important:** Use -999, NOT -1000 for the parent. A value of -1000 makes the process completely immune to the OOM killer. If all children are dead and the parent alone exceeds the memory limit, the cgroup enters an unkillable OOM state and the container hangs indefinitely.

**Capability requirement:** Writing to `oom_score_adj` requires either running as root inside the container or the `SYS_RESOURCE` Linux capability. If the container runs as non-root, add the capability in the pod spec:

```yaml
securityContext:
  capabilities:
    add: ["SYS_RESOURCE"]
```

### Part 2: Graceful Child Death Handling (Critical)

The `oom_score_adj` fix alone is insufficient. kubevuln (PID 1) **must** handle child process death gracefully. Without this, the parent will still exit/crash when a child is OOM-killed, causing a pod restart regardless of OOM score settings.

The orchestrator should:

- Catch SIGCHLD / monitor child exit status
- Detect OOM-kill specifically (exit status will indicate SIGKILL; can also check `/proc/<pid>/oom_score` before death or `dmesg`/kernel logs)
- Log the OOM event with the child's identity and memory usage
- Decide on recovery action: retry the scan, queue it for later, or report failure
- **Continue running** — do not exit or panic

```go
// Pseudocode for the orchestrator's child monitoring loop
if waitStatus.Signaled() && waitStatus.Signal() == syscall.SIGKILL {
    // Likely OOM-killed — log and recover
    log.Warnf("child %d was OOM-killed, will retry", childPID)
    // Re-queue the work or report partial failure
} else {
    // Normal exit or other signal — handle accordingly
}
```

## How the Kernel OOM Killer Selects a Victim

Within a cgroup (container), the kernel computes `oom_badness()` for every process. The score is primarily based on:

1. **RSS (Resident Set Size)** — the process using the most physical memory gets the highest base score
2. **`oom_score_adj`** — a tunable per-process modifier (range: -1000 to +1000) that inflates or deflates the score

The process with the highest combined score is killed first. With the configuration above (-999 for parent, +1000 for children), the children will always be selected before the parent.

## cgroup v2 Note

On cgroup v2 systems, there is an additional knob: `memory.oom.group`. If set to 1, the kernel kills **all** processes in the cgroup together instead of selecting a single victim. The default is 0 (single-victim selection). Kubernetes does not set this to 1 by default, so the per-process selection behavior described above applies.

## Kubernetes OOM Score Context

Kubelet sets `oom_score_adj` at the **pod** level based on QoS class:

- Guaranteed: -997
- Burstable: scaled between -997 and 1000
- BestEffort: 1000

The per-process tuning described in this document operates **within** the container's cgroup, on top of whatever kubelet has set for the pod. This is fine — the kernel evaluates scores within the cgroup scope during OOM events.

## Verification

After implementing, verify the fix:

1. `cat /proc/<kubevuln-pid>/oom_score_adj` should show -999
2. `cat /proc/<worker-pid>/oom_score_adj` should show 1000
3. Trigger OOM by scanning a large image (e.g., `gitlab/gitlab-ee`)
4. Confirm: worker is killed, kubevuln remains running, pod does NOT restart
5. Check `kubectl describe pod` — should NOT show `OOMKilled` as pod termination reason (individual process OOM kill won't surface here if the pod survives)