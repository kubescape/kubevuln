package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/moby/sys/reexec"
)

const (
	// sbomWorkerName is the reexec handler name for the SBOM worker subprocess.
	sbomWorkerName = "sbom-worker"

	// parentTimeoutBuffer is the extra time the parent waits beyond the child's
	// scan timeout, so the child can return a clean timeout error before the
	// parent kills it.
	parentTimeoutBuffer = 30 * time.Second
)

func init() {
	reexec.Register(sbomWorkerName, runSBOMWorker)
}

// InitReexec checks whether the current process was re-exec'd as a registered
// handler. Call this at the top of main(). If it returns true, the handler has
// already run and main() should return immediately.
func InitReexec() bool {
	return reexec.Init()
}

// SubprocessSBOMCreator wraps SyftAdapter and delegates SBOM creation to a
// child process via moby/sys/reexec. If the child is OOM-killed (SIGKILL),
// the parent survives and returns a recognizable error. When subprocess mode
// is disabled, it falls back to the inner SyftAdapter directly.
type SubprocessSBOMCreator struct {
	inner       *SyftAdapter
	timeout     time.Duration
	memoryLimit int64 // child process memory limit in bytes (0 = no limit)
	enabled     bool

	mu       sync.Mutex
	children []*exec.Cmd // tracked for SIGTERM propagation
}

var _ ports.SBOMCreator = (*SubprocessSBOMCreator)(nil)

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

// sbomWorkerRequest is the JSON payload sent to the child process via a pipe.
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

// sbomWorkerResponse is the JSON payload the child process writes back via a pipe.
type sbomWorkerResponse struct {
	SBOM  *domain.SBOM `json:"sbom,omitempty"`
	Error string       `json:"error,omitempty"`
}

// Sentinel errors for classifying child process failures.
var (
	// ErrChildOOMKilled is returned when the child process was killed by SIGKILL,
	// which typically indicates an OOM kill.
	ErrChildOOMKilled = errors.New("SBOM creation child process was OOM-killed (SIGKILL)")

	// ErrChildSignaled is returned when the child process was killed by a signal
	// other than SIGKILL.
	ErrChildSignaled = errors.New("SBOM creation child process was killed by signal")

	// ErrChildTimeout is returned when the child process exceeds its timeout.
	ErrChildTimeout = errors.New("SBOM creation child process timed out")
)

func (s *SubprocessSBOMCreator) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	if !s.enabled {
		return s.inner.CreateSBOM(ctx, name, imageID, imageTag, options)
	}
	return s.createSBOMInSubprocess(ctx, name, imageID, imageTag, options)
}

func (s *SubprocessSBOMCreator) Version() string {
	return s.inner.Version()
}

// Shutdown sends SIGTERM to all active child processes. Call this during
// graceful shutdown of the parent (e.g., when Kubernetes sends SIGTERM).
func (s *SubprocessSBOMCreator) Shutdown() {
	s.mu.Lock()
	children := append([]*exec.Cmd{}, s.children...)
	s.mu.Unlock()

	for _, cmd := range children {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}
}

func (s *SubprocessSBOMCreator) trackChild(cmd *exec.Cmd) {
	s.mu.Lock()
	s.children = append(s.children, cmd)
	s.mu.Unlock()
}

func (s *SubprocessSBOMCreator) untrackChild(cmd *exec.Cmd) {
	s.mu.Lock()
	for i, c := range s.children {
		if c == cmd {
			s.children = append(s.children[:i], s.children[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
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

	// Create pipes for IPC. These are separate from stdout/stderr, so the
	// child can log freely to stdout/stderr without corrupting the data channel.
	reqReader, reqWriter, err := os.Pipe()
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("failed to create request pipe: %w", err)
	}
	defer reqReader.Close()

	respReader, respWriter, err := os.Pipe()
	if err != nil {
		reqWriter.Close()
		return domain.SBOM{}, fmt.Errorf("failed to create response pipe: %w", err)
	}
	defer respWriter.Close()

	// Give the parent extra time so the child can return a clean timeout
	// error before the parent force-kills it.
	childCtx, cancel := context.WithTimeout(ctx, s.timeout+parentTimeoutBuffer)
	defer cancel()

	cmd := reexec.Command(sbomWorkerName)
	cmd.ExtraFiles = []*os.File{reqReader, respWriter} // FD 3 = request, FD 4 = response
	cmd.Env = os.Environ()

	// Set memory limit on the child process if configured.
	if s.memoryLimit > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("KUBEVULN_SBOM_WORKER_MEMLIMIT=%d", s.memoryLimit))
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logger.L().Ctx(ctx).Info("spawning SBOM worker subprocess",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag))

	if err := cmd.Start(); err != nil {
		reqWriter.Close()
		respReader.Close()
		return domain.SBOM{}, fmt.Errorf("failed to start worker subprocess: %w", err)
	}

	s.trackChild(cmd)
	defer s.untrackChild(cmd)

	// Close the parent's copy of the child's read/write ends.
	reqReader.Close()
	respWriter.Close()

	// Write request to child via pipe, then close to signal EOF.
	if _, err := reqWriter.Write(reqBytes); err != nil {
		reqWriter.Close()
		respReader.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return domain.SBOM{}, fmt.Errorf("failed to write request to worker: %w", err)
	}
	reqWriter.Close()

	// Read response from child via pipe.
	respBytes, readErr := io.ReadAll(respReader)
	respReader.Close()

	// Wait for child to exit.
	waitErr := cmd.Wait()

	// Check for context timeout first (parent-side kill).
	if childCtx.Err() == context.DeadlineExceeded {
		cleanupOrphanedTempDirs(ctx)
		logger.L().Ctx(ctx).Error("SBOM worker subprocess timed out",
			helpers.String("imageID", imageID),
			helpers.String("stderr", stderr.String()))
		return domain.SBOM{}, ErrChildTimeout
	}

	if waitErr != nil {
		cleanupOrphanedTempDirs(ctx)
		return s.handleChildError(ctx, waitErr, imageID, stderr.String())
	}

	if readErr != nil {
		return domain.SBOM{}, fmt.Errorf("failed to read worker response: %w (stderr: %s)", readErr, stderr.String())
	}

	var resp sbomWorkerResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
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

func (s *SubprocessSBOMCreator) handleChildError(ctx context.Context, err error, imageID, stderrOutput string) (domain.SBOM, error) {
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

// runSBOMWorker is the reexec handler for the child process.
// It reads a request from the pipe (FD 3), creates the SBOM, and writes the
// result to the response pipe (FD 4).
func runSBOMWorker() {
	applyMemoryLimit()

	// FD 3 = request pipe, FD 4 = response pipe (set by parent via ExtraFiles).
	reqPipe := os.NewFile(3, "req-pipe")
	respPipe := os.NewFile(4, "resp-pipe")
	if reqPipe == nil || respPipe == nil {
		fmt.Fprintf(os.Stderr, "sbom-worker: missing pipe file descriptors\n")
		os.Exit(1)
	}
	defer reqPipe.Close()
	defer respPipe.Close()

	var req sbomWorkerRequest
	if err := json.NewDecoder(reqPipe).Decode(&req); err != nil {
		writeWorkerError(respPipe, fmt.Sprintf("failed to decode request: %v", err))
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

	if err := json.NewEncoder(respPipe).Encode(resp); err != nil {
		writeWorkerError(respPipe, fmt.Sprintf("failed to encode response: %v", err))
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
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, rlimit); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to set memory limit: %v\n", err)
	}
}

func writeWorkerError(w io.Writer, msg string) {
	resp := sbomWorkerResponse{Error: msg}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
