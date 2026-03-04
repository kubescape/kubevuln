package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

// SubprocessSBOMCreator wraps SyftAdapter and delegates SBOM creation to a
// child process. If the child is OOM-killed (SIGKILL), the parent survives
// and returns a recognizable error. When subprocess mode is disabled, it
// falls back to the inner SyftAdapter directly.
type SubprocessSBOMCreator struct {
	inner       *SyftAdapter
	timeout     time.Duration
	memoryLimit int64 // child process memory limit in bytes (0 = no limit)
	enabled     bool
}

var _ ports.SBOMCreator = (*SubprocessSBOMCreator)(nil)

// parentTimeoutBuffer is the extra time the parent waits beyond the child's
// scan timeout, so the child can return a clean timeout error before the
// parent kills it.
const parentTimeoutBuffer = 30 * time.Second

// NewSubprocessSBOMCreator creates a new SubprocessSBOMCreator.
// When enabled=true, SBOM creation runs in a child process.
// When enabled=false, it delegates directly to the inner SyftAdapter.
// memoryLimit sets RLIMIT_AS on the child process (0 = no limit).
func NewSubprocessSBOMCreator(inner *SyftAdapter, timeout time.Duration, memoryLimit int64, enabled bool) *SubprocessSBOMCreator {
	return &SubprocessSBOMCreator{
		inner:       inner,
		timeout:     timeout,
		memoryLimit: memoryLimit,
		enabled:     enabled,
	}
}

// sbomWorkerRequest is the JSON payload sent to the child process via stdin.
type sbomWorkerRequest struct {
	Name     string                 `json:"name"`
	ImageID  string                 `json:"imageID"`
	ImageTag string                 `json:"imageTag"`
	Options  domain.RegistryOptions `json:"options"`
	// SyftAdapter config (child needs to reconstruct the adapter).
	ScanTimeout       time.Duration `json:"scanTimeout"`
	MaxImageSize      int64         `json:"maxImageSize"`
	MaxSBOMSize       int           `json:"maxSBOMSize"`
	ScanEmbeddedSBOMs bool          `json:"scanEmbeddedSBOMs"`
}

// sbomWorkerResponse is the JSON payload the child process writes to stdout.
type sbomWorkerResponse struct {
	SBOM  *domain.SBOM `json:"sbom,omitempty"`
	Error string       `json:"error,omitempty"`
}

// ErrChildOOMKilled is returned when the child process was killed by SIGKILL,
// which typically indicates an OOM kill.
var ErrChildOOMKilled = errors.New("SBOM creation child process was OOM-killed (SIGKILL)")

// ErrChildSignaled is returned when the child process was killed by a signal
// other than SIGKILL.
var ErrChildSignaled = errors.New("SBOM creation child process was killed by signal")

// ErrChildTimeout is returned when the child process exceeds its timeout.
var ErrChildTimeout = errors.New("SBOM creation child process timed out")

func (s *SubprocessSBOMCreator) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	if !s.enabled {
		return s.inner.CreateSBOM(ctx, name, imageID, imageTag, options)
	}
	return s.createSBOMInSubprocess(ctx, name, imageID, imageTag, options)
}

func (s *SubprocessSBOMCreator) Version() string {
	return s.inner.Version()
}

func (s *SubprocessSBOMCreator) createSBOMInSubprocess(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	req := sbomWorkerRequest{
		Name:              name,
		ImageID:           imageID,
		ImageTag:          imageTag,
		Options:           options,
		ScanTimeout:       s.inner.scanTimeout,
		MaxImageSize:      s.inner.maxImageSize,
		MaxSBOMSize:       s.inner.maxSBOMSize,
		ScanEmbeddedSBOMs: s.inner.scanEmbeddedSBOMs,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("failed to marshal worker request: %w", err)
	}

	// Self-re-exec with worker env var.
	executable, err := os.Executable()
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Give the parent extra time so the child can return a clean timeout
	// error before the parent force-kills it.
	childCtx, cancel := context.WithTimeout(ctx, s.timeout+parentTimeoutBuffer)
	defer cancel()

	cmd := exec.CommandContext(childCtx, executable)
	cmd.Stdin = bytes.NewReader(reqBytes)
	cmd.Env = append(os.Environ(), "KUBEVULN_SBOM_WORKER=1")

	// Set memory limit on the child process if configured.
	if s.memoryLimit > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.Env = append(cmd.Env, fmt.Sprintf("KUBEVULN_SBOM_WORKER_MEMLIMIT=%d", s.memoryLimit))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.L().Ctx(ctx).Info("spawning SBOM worker subprocess",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag))

	err = cmd.Run()
	if err != nil {
		// Clean up orphaned temp dirs left by the killed child.
		cleanupOrphanedTempDirs(ctx)
		return s.handleChildError(ctx, err, childCtx, imageID, stderr.String())
	}

	var resp sbomWorkerResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return domain.SBOM{}, fmt.Errorf("failed to unmarshal worker response: %w (stderr: %s)", err, stderr.String())
	}

	if resp.Error != "" {
		return domain.SBOM{}, fmt.Errorf("worker error: %s", resp.Error)
	}

	if resp.SBOM == nil {
		return domain.SBOM{}, nil
	}

	return *resp.SBOM, nil
}

func (s *SubprocessSBOMCreator) handleChildError(ctx context.Context, err error, childCtx context.Context, imageID, stderrOutput string) (domain.SBOM, error) {
	// Check if the context timed out.
	if childCtx.Err() == context.DeadlineExceeded {
		logger.L().Ctx(ctx).Error("SBOM worker subprocess timed out",
			helpers.String("imageID", imageID),
			helpers.String("stderr", stderrOutput))
		return domain.SBOM{}, ErrChildTimeout
	}

	// Check exit error for signal information.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				sig := status.Signal()
				logger.L().Ctx(ctx).Error("SBOM worker subprocess killed by signal",
					helpers.String("imageID", imageID),
					helpers.String("signal", sig.String()),
					helpers.String("stderr", stderrOutput))
				if sig == syscall.SIGKILL {
					return domain.SBOM{}, ErrChildOOMKilled
				}
				return domain.SBOM{}, fmt.Errorf("%w: %s", ErrChildSignaled, sig.String())
			}
		}
		logger.L().Ctx(ctx).Error("SBOM worker subprocess exited with error",
			helpers.String("imageID", imageID),
			helpers.Int("exitCode", exitErr.ExitCode()),
			helpers.String("stderr", stderrOutput))
	}

	return domain.SBOM{}, fmt.Errorf("SBOM worker subprocess failed: %w (stderr: %s)", err, stderrOutput)
}

// cleanupOrphanedTempDirs removes temporary directories left by a killed child
// process. Stereoscope creates temp dirs with prefix "stereoscope" under os.TempDir().
func cleanupOrphanedTempDirs(ctx context.Context) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "stereoscope") {
			path := filepath.Join(os.TempDir(), entry.Name())
			if err := os.RemoveAll(path); err != nil {
				logger.L().Ctx(ctx).Warning("failed to cleanup orphaned temp dir",
					helpers.String("path", path),
					helpers.Error(err))
			} else {
				logger.L().Ctx(ctx).Debug("cleaned up orphaned temp dir",
					helpers.String("path", path))
			}
		}
	}
}

// RunSBOMWorker is the entry point for the child process.
// It reads a request from stdin, creates the SBOM, and writes the result to stdout.
// On error, it writes an error response and exits with code 1.
func RunSBOMWorker() {
	// Apply memory limit if set by parent.
	applyMemoryLimit()

	var req sbomWorkerRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		writeWorkerError(fmt.Sprintf("failed to decode request: %v", err))
		os.Exit(1)
	}

	adapter := NewSyftAdapter(req.ScanTimeout, req.MaxImageSize, req.MaxSBOMSize, req.ScanEmbeddedSBOMs)

	ctx, cancel := context.WithTimeout(context.Background(), req.ScanTimeout)
	defer cancel()

	sbom, err := adapter.CreateSBOM(ctx, req.Name, req.ImageID, req.ImageTag, req.Options)

	resp := sbomWorkerResponse{SBOM: &sbom}
	if err != nil {
		resp.Error = err.Error()
	}

	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		writeWorkerError(fmt.Sprintf("failed to encode response: %v", err))
		os.Exit(1)
	}
}

// applyMemoryLimit sets RLIMIT_AS on the current process if the parent
// passed a memory limit via environment variable.
func applyMemoryLimit() {
	limitStr := os.Getenv("KUBEVULN_SBOM_WORKER_MEMLIMIT")
	if limitStr == "" {
		return
	}
	var limit int64
	if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || limit <= 0 {
		return
	}
	rlimit := &syscall.Rlimit{
		Cur: uint64(limit),
		Max: uint64(limit),
	}
	// RLIMIT_AS limits the virtual address space.  If the limit is hit,
	// memory allocations fail (mmap returns ENOMEM) which usually leads
	// to the Go runtime crashing or the OOM killer stepping in.
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, rlimit); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to set memory limit: %v\n", err)
	}
}

func writeWorkerError(msg string) {
	resp := sbomWorkerResponse{Error: msg}
	json.NewEncoder(os.Stdout).Encode(resp) //nolint:errcheck
}
