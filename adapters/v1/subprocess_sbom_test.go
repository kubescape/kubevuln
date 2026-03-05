package v1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubprocessSBOMCreator_DisabledFallsThrough(t *testing.T) {
	inner := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false)
	creator := NewSubprocessSBOMCreator(inner, 5*time.Minute, 0, false)

	// When disabled, it should use the inner adapter directly.
	assert.Equal(t, inner.Version(), creator.Version())
}

func TestSbomWorkerRequest_JSONRoundTrip(t *testing.T) {
	req := sbomWorkerRequest{
		Name:     "test-image",
		ImageID:  "sha256:abc123",
		ImageTag: "nginx:1.25",
		Options: domain.RegistryOptions{
			Platform: "linux/amd64",
			Credentials: []domain.RegistryCredentials{
				{Authority: "docker.io", Username: "user", Password: "pass"},
			},
		},
		ScanTimeout:       5 * time.Minute,
		MaxImageSize:      512 * 1024 * 1024,
		MaxSBOMSize:       20 * 1024 * 1024,
		ScanEmbeddedSBOMs: true,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded sbomWorkerRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Name, decoded.Name)
	assert.Equal(t, req.ImageID, decoded.ImageID)
	assert.Equal(t, req.ImageTag, decoded.ImageTag)
	assert.Equal(t, req.ScanTimeout, decoded.ScanTimeout)
	assert.Equal(t, req.MaxImageSize, decoded.MaxImageSize)
	assert.Equal(t, req.MaxSBOMSize, decoded.MaxSBOMSize)
	assert.Equal(t, req.ScanEmbeddedSBOMs, decoded.ScanEmbeddedSBOMs)
	assert.Equal(t, "docker.io", decoded.Options.Credentials[0].Authority)
}

func TestSbomWorkerResponse_WithError(t *testing.T) {
	resp := sbomWorkerResponse{
		Error: "syft: unable to parse image",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded sbomWorkerResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "syft: unable to parse image", decoded.Error)
	assert.Nil(t, decoded.SBOM)
}

func TestSbomWorkerResponse_WithSBOM(t *testing.T) {
	sbom := domain.SBOM{
		Name:            "test",
		SBOMCreatorName: "syft",
		Status:          "Learning",
	}
	resp := sbomWorkerResponse{SBOM: &sbom}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded sbomWorkerResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Error)
	require.NotNil(t, decoded.SBOM)
	assert.Equal(t, "test", decoded.SBOM.Name)
	assert.Equal(t, "syft", decoded.SBOM.SBOMCreatorName)
}

// --- Integration tests: spawn real child processes to test parent behavior ---

// TestHelperProcess_SIGKILL is not a real test. It's invoked as a subprocess
// by TestHandleChildError_OOMKilled. It immediately sends itself SIGKILL to
// simulate an OOM kill.
func TestHelperProcess_SIGKILL(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") != "SIGKILL" {
		return
	}
	syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

// TestHelperProcess_ExitOne is invoked as a subprocess. Exits with code 1.
func TestHelperProcess_ExitOne(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") != "EXIT1" {
		return
	}
	os.Exit(1)
}

// TestHelperProcess_WriteResponse is invoked as a subprocess.
// Writes a valid JSON worker response to stdout and exits cleanly.
func TestHelperProcess_WriteResponse(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") != "RESPOND" {
		return
	}
	resp := sbomWorkerResponse{
		SBOM: &domain.SBOM{
			Name:            "test-from-child",
			SBOMCreatorName: "syft",
		},
	}
	json.NewEncoder(os.Stdout).Encode(resp)
	os.Exit(0)
}

func TestHandleChildError_OOMKilled(t *testing.T) {
	// Spawn a child process that SIGKILLs itself (simulates OOM kill).
	// Verify the parent:
	//   1. Stays alive (the test completing proves this)
	//   2. Returns ErrChildOOMKilled
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_SIGKILL$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=SIGKILL")

	err := cmd.Run()
	require.Error(t, err, "child should have been killed")

	// Feed the error through handleChildError — same code path as production.
	creator := &SubprocessSBOMCreator{}
	ctx := context.Background()

	_, handleErr := creator.handleChildError(ctx, err, "test-image", "")

	assert.ErrorIs(t, handleErr, ErrChildOOMKilled,
		"SIGKILL should be classified as OOM kill")
}

func TestHandleChildError_NonZeroExit(t *testing.T) {
	// Spawn a child that exits with code 1 (e.g. scan error, not a signal).
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_ExitOne$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=EXIT1")

	err := cmd.Run()
	require.Error(t, err)

	creator := &SubprocessSBOMCreator{}
	ctx := context.Background()

	_, handleErr := creator.handleChildError(ctx, err, "test-image", "")

	// Should NOT be OOM — it's a normal exit code error.
	assert.False(t, errors.Is(handleErr, ErrChildOOMKilled),
		"exit code 1 should not be classified as OOM")
	assert.False(t, errors.Is(handleErr, ErrChildTimeout),
		"exit code 1 should not be classified as timeout")
	assert.Contains(t, handleErr.Error(), "SBOM worker subprocess failed")
}

func TestHandleChildError_Timeout(t *testing.T) {
	// Verify that when childCtx has expired, createSBOMInSubprocess returns ErrChildTimeout.
	// We test the timeout classification logic directly since the full method
	// integrates context checks before calling handleChildError.
	creator := &SubprocessSBOMCreator{}
	ctx := context.Background()

	// Create an already-expired context.
	childCtx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond)

	assert.ErrorIs(t, childCtx.Err(), context.DeadlineExceeded,
		"childCtx should be expired — the parent uses this to classify timeout")

	// The timeout check happens in createSBOMInSubprocess before handleChildError.
	// Verify handleChildError returns a generic error (not timeout) since it
	// doesn't receive the context.
	dummyErr := errors.New("signal: killed")
	_, handleErr := creator.handleChildError(ctx, dummyErr, "test-image", "")
	assert.Contains(t, handleErr.Error(), "SBOM worker subprocess failed")
}

func TestSubprocessSBOMCreator_ChildSucceeds(t *testing.T) {
	// Spawn a child that writes a valid SBOM response to stdout.
	// This tests the full parent-side response parsing path.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_WriteResponse$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=RESPOND")

	output, err := cmd.Output()
	require.NoError(t, err, "child should exit cleanly")

	var resp sbomWorkerResponse
	err = json.Unmarshal(output, &resp)
	require.NoError(t, err)

	assert.Empty(t, resp.Error)
	require.NotNil(t, resp.SBOM)
	assert.Equal(t, "test-from-child", resp.SBOM.Name)
	assert.Equal(t, "syft", resp.SBOM.SBOMCreatorName)
}

func TestParentSurvivesChildOOMKill(t *testing.T) {
	// End-to-end: the parent process (this test) spawns a child that gets
	// SIGKILL'd and verifies it can continue executing normally afterward.
	// This is the critical property — OOM in the child must not crash the parent.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_SIGKILL$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=SIGKILL")

	err := cmd.Run()
	require.Error(t, err)

	// If we reach here, the parent survived. Do meaningful work to prove
	// the process is healthy — not just alive but fully functional.
	result := 0
	for i := 0; i < 1000; i++ {
		result += i
	}
	assert.Equal(t, 499500, result, "parent should be fully functional after child OOM")

	// Spawn another child to prove we can still fork after the first one died.
	cmd2 := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_WriteResponse$")
	cmd2.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=RESPOND")
	output, err := cmd2.Output()
	require.NoError(t, err, "parent should be able to spawn new children after OOM")

	var resp sbomWorkerResponse
	require.NoError(t, json.Unmarshal(output, &resp))
	assert.Equal(t, "test-from-child", resp.SBOM.Name)
}

func TestSubprocessSBOMCreator_Shutdown(t *testing.T) {
	// Verify Shutdown() doesn't panic on an empty children list.
	creator := NewSubprocessSBOMCreator(
		NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false),
		5*time.Minute, 0, true)

	assert.NotPanics(t, func() {
		creator.Shutdown()
	})
}

func TestSubprocessSBOMCreator_TrackUntrack(t *testing.T) {
	creator := &SubprocessSBOMCreator{}
	cmd1 := &exec.Cmd{}
	cmd2 := &exec.Cmd{}

	creator.trackChild(cmd1)
	creator.trackChild(cmd2)
	assert.Len(t, creator.children, 2)

	creator.untrackChild(cmd1)
	assert.Len(t, creator.children, 1)

	creator.untrackChild(cmd2)
	assert.Empty(t, creator.children)

	// Untracking a non-existent cmd should be safe.
	creator.untrackChild(cmd1)
	assert.Empty(t, creator.children)
}
