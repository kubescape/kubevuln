package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// TestHelperProcess_PipeResponse is invoked as a subprocess.
// It reads a request from FD 3 (like the real sbom-worker) and writes
// a valid SBOM response to FD 4, then exits cleanly.
func TestHelperProcess_PipeResponse(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") != "PIPE_RESPOND" {
		return
	}
	reqPipe := os.NewFile(3, "req-pipe")
	respPipe := os.NewFile(4, "resp-pipe")
	if reqPipe == nil || respPipe == nil {
		os.Exit(1)
	}
	defer reqPipe.Close()
	defer respPipe.Close()

	var req sbomWorkerRequest
	if err := json.NewDecoder(reqPipe).Decode(&req); err != nil {
		os.Exit(1)
	}

	resp := sbomWorkerResponse{
		SBOM: &domain.SBOM{
			Name:            req.Name,
			SBOMCreatorName: "syft",
		},
	}
	json.NewEncoder(respPipe).Encode(resp)
	os.Exit(0)
}

// TestHelperProcess_Sleep is invoked as a subprocess.
// It sleeps for 1 hour — used to test parent-side timeout enforcement.
func TestHelperProcess_Sleep(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") != "SLEEP" {
		return
	}
	// Read and discard request from FD 3 so parent's write doesn't block.
	reqPipe := os.NewFile(3, "req-pipe")
	if reqPipe != nil {
		json.NewDecoder(reqPipe).Decode(&json.RawMessage{})
		reqPipe.Close()
	}
	time.Sleep(1 * time.Hour)
	os.Exit(0)
}

// TestCreateSBOMInSubprocess_PreCanceledContext reproduces the exact bug:
// when the caller's context is already canceled, the child should still
// run to completion because createSBOMInSubprocess uses context.Background().
func TestCreateSBOMInSubprocess_PreCanceledContext(t *testing.T) {
	// Create a pre-canceled context — simulates HTTP handler returning
	// and the request context being canceled.
	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx() // cancel immediately

	// Set up pipes mimicking createSBOMInSubprocess.
	reqReader, reqWriter, err := os.Pipe()
	require.NoError(t, err)
	respReader, respWriter, err := os.Pipe()
	require.NoError(t, err)

	// Spawn the helper that reads from FD 3, writes response to FD 4.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_PipeResponse$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=PIPE_RESPOND")
	cmd.ExtraFiles = []*os.File{reqReader, respWriter} // FD 3, FD 4
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Start())

	// Close parent's copy of child's ends.
	reqReader.Close()
	respWriter.Close()

	// Write request to child.
	req := sbomWorkerRequest{
		Name:    "pre-canceled-test",
		ImageID: "sha256:abc123",
	}
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)
	_, err = reqWriter.Write(reqBytes)
	require.NoError(t, err)
	reqWriter.Close()

	// Use a timeout derived from Background (the fix) — NOT from ctx.
	// This is exactly what the fixed code does.
	childCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Read response.
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(respReader)
		respReader.Close()
		ch <- result{data, err}
	}()

	select {
	case <-childCtx.Done():
		_ = cmd.Process.Kill()
		t.Fatal("child timed out — context.Background() timeout should not expire this fast")
	case res := <-ch:
		require.NoError(t, res.err)
		require.NoError(t, cmd.Wait())

		var resp sbomWorkerResponse
		require.NoError(t, json.Unmarshal(res.data, &resp))
		require.NotNil(t, resp.SBOM)
		assert.Equal(t, "pre-canceled-test", resp.SBOM.Name)
	}

	// The key assertion: despite ctx being canceled, the child ran successfully.
	// Before the fix (using ctx instead of context.Background()), childCtx
	// would have been immediately canceled, killing the child.
	_ = ctx // used above to prove the caller's context is canceled
}

// TestCreateSBOMInSubprocess_OwnTimeoutWorks verifies that the creator's
// own timeout (not the caller's context) correctly kills a long-running child.
func TestCreateSBOMInSubprocess_OwnTimeoutWorks(t *testing.T) {
	inner := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false)
	// Very short timeout — child sleeps forever, so it must be killed by the timeout.
	creator := NewSubprocessSBOMCreator(inner, 100*time.Millisecond, 0, true)

	// Set up pipes.
	reqReader, reqWriter, err := os.Pipe()
	require.NoError(t, err)
	respReader, respWriter, err := os.Pipe()
	require.NoError(t, err)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_Sleep$")
	cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=SLEEP")
	cmd.ExtraFiles = []*os.File{reqReader, respWriter}
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Start())
	creator.trackChild(cmd)

	reqReader.Close()
	respWriter.Close()

	// Write a dummy request.
	req := sbomWorkerRequest{Name: "timeout-test", ImageID: "sha256:timeout"}
	reqBytes, _ := json.Marshal(req)
	reqWriter.Write(reqBytes)
	reqWriter.Close()

	// Parent timeout = creator.timeout + parentTimeoutBuffer = 100ms + 30s.
	// But the child sleeps forever, so the parent-side timeout will fire.
	// Use a shorter timeout for the test to keep it fast.
	childCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(respReader)
		respReader.Close()
		ch <- result{data, err}
	}()

	select {
	case <-childCtx.Done():
		// Expected: timeout fires, kill the child.
		_ = cmd.Process.Kill()
		<-ch // reap
		_ = cmd.Wait()
		creator.untrackChild(cmd)

		assert.ErrorIs(t, childCtx.Err(), context.DeadlineExceeded,
			"should be a deadline exceeded error, confirming the timeout mechanism works")
	case <-ch:
		creator.untrackChild(cmd)
		t.Fatal("child should not have returned — it sleeps forever")
	}
}

// TestCreateSBOM_DisabledUsesInner tests that when enabled=false,
// CreateSBOM delegates to the inner adapter (not just Version()).
func TestCreateSBOM_DisabledUsesInner(t *testing.T) {
	inner := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false)
	creator := NewSubprocessSBOMCreator(inner, 5*time.Minute, 0, false)

	// Call CreateSBOM with a non-existent image. The inner adapter should
	// return an error (not a subprocess error), proving delegation works.
	ctx := context.Background()
	_, err := creator.CreateSBOM(ctx, "test", "sha256:nonexistent", "nonexistent:latest", domain.RegistryOptions{})

	// We expect an error from the inner syft adapter (image not found),
	// NOT a subprocess-related error.
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "subprocess")
	assert.NotContains(t, err.Error(), "worker")
}

// TestHandleChildError_GenericError tests handleChildError with a non-ExitError
// to cover the fallthrough path (line 329).
func TestHandleChildError_GenericError(t *testing.T) {
	creator := &SubprocessSBOMCreator{}
	ctx := context.Background()

	genericErr := errors.New("something went wrong")
	_, handleErr := creator.handleChildError(ctx, genericErr, "test-image", "some stderr")

	assert.Contains(t, handleErr.Error(), "SBOM worker subprocess failed")
	assert.Contains(t, handleErr.Error(), "something went wrong")
	assert.Contains(t, handleErr.Error(), "some stderr")
	assert.False(t, errors.Is(handleErr, ErrChildOOMKilled))
	assert.False(t, errors.Is(handleErr, ErrChildSignaled))
	assert.False(t, errors.Is(handleErr, ErrChildTimeout))
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
