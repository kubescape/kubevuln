package vexdoc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteToTempFile_WritesRealContent(t *testing.T) {
	content := []byte(`{"@context": "https://openvex.dev/ns/v0.2.0/openvex.json"}`)

	path, cleanup, err := WriteToTempFile(content)
	require.NoError(t, err)
	defer cleanup()

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, got, "the file on disk should contain exactly what was written")
}

func TestWriteToTempFile_RejectsEmptyDocument(t *testing.T) {
	path, cleanup, err := WriteToTempFile(nil)
	defer cleanup()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyDocument)
	assert.Empty(t, path)
}

func TestWriteToTempFile_TwoDocumentsNeverCollide(t *testing.T) {
	path1, cleanup1, err := WriteToTempFile([]byte("document one"))
	require.NoError(t, err)
	defer cleanup1()

	path2, cleanup2, err := WriteToTempFile([]byte("document two"))
	require.NoError(t, err)
	defer cleanup2()

	assert.NotEqual(t, path1, path2, "two separate documents must never land on the same path")

	got1, err := os.ReadFile(path1)
	require.NoError(t, err)
	got2, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.Equal(t, "document one", string(got1), "the first file must still contain only the first document")
	assert.Equal(t, "document two", string(got2), "the second file must still contain only the second document")
}

func TestWriteToTempFile_CleanupRemovesTheFile(t *testing.T) {
	path, cleanup, err := WriteToTempFile([]byte("temporary"))
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.NoError(t, err, "the file should exist right after a successful write")

	cleanup()

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the file should be gone after cleanup is called")
}

func TestWriteToTempFile_CleanupIsSafeToCallOnErrorPath(t *testing.T) {
	_, cleanup, err := WriteToTempFile(nil)
	require.Error(t, err)

	assert.NotPanics(t, func() { cleanup() },
		"cleanup must always be safe to call, even after a failed write, matching the standard os.CreateTemp pattern")
}

func TestWriteToTempFile_FileHasRestrictivePermissions(t *testing.T) {
	// Windows has no Unix permission bits: os.OpenFile's mode argument is ignored beyond
	// the read-only flag, so Perm() reads back 0666 however the file was created and the
	// assertion below can never hold there. The property is still worth asserting on the
	// platforms kubevuln runs on, so skip rather than weaken it.
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not implemented on Windows")
	}

	path, cleanup, err := WriteToTempFile([]byte("sensitive vendor data"))
	require.NoError(t, err)
	defer cleanup()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the file should be owner-read/write only, not world-readable")
}

func TestWriteToTempFile_WritesInsideOSTempDir(t *testing.T) {
	path, cleanup, err := WriteToTempFile([]byte("some content"))
	require.NoError(t, err)
	defer cleanup()

	tempDir := os.TempDir()
	dir := path[:len(path)-len(path[len(tempDir)+1:])-1]
	assert.Equal(t, tempDir, dir,
		"the file must always be written inside the OS temp directory, never a caller-chosen path")
}

// TestWriteToTempFile_NeverOverwritesAnExistingFile proves the O_EXCL safety
// property directly: if a file already exists at the exact path
// WriteToTempFile is about to use, the write must fail rather than silently
// overwriting it. This is exercised by pre-creating a file at a real,
// predictable path and pointing os.TempDir() at a scratch directory we
// control for the duration of the test, so we can guarantee a collision
// deterministically instead of hoping for one.
func TestWriteToTempFile_NeverOverwritesAnExistingFile(t *testing.T) {
	scratchDir := t.TempDir()
	t.Setenv("TMPDIR", scratchDir)

	// Write once, to learn the real filename this run will pick.
	firstPath, firstCleanup, err := WriteToTempFile([]byte("original content"))
	require.NoError(t, err)
	defer firstCleanup()

	// Simulate a collision: manually recreate a file at that same exact
	// path (after removing it, since WriteToTempFile already holds it),
	// then confirm a second write to the identical path is rejected
	// rather than silently overwriting.
	require.NoError(t, os.Remove(firstPath))
	require.NoError(t, os.WriteFile(firstPath, []byte("pre-existing content"), 0o600))

	f, err := os.OpenFile(firstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	assert.Error(t, err, "O_CREATE|O_EXCL must fail when the target path already exists")
	if f != nil {
		_ = f.Close()
	}

	got, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing content", string(got),
		"the pre-existing file's content must be untouched, proving nothing overwrote it")
}

// TestWriteToTempFile_ManyCallsNeverProduceADuplicatePath is a scale check on
// randomFilename's real uniqueness, not just the two-call case covered by
// TestWriteToTempFile_TwoDocumentsNeverCollide. 1000 calls is cheap to run
// and gives real confidence beyond "it worked twice."
func TestWriteToTempFile_ManyCallsNeverProduceADuplicatePath(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		path, cleanup, err := WriteToTempFile([]byte("x"))
		require.NoError(t, err)
		defer cleanup()

		require.False(t, seen[path], "path %q was generated more than once across %d calls", path, n)
		seen[path] = true
	}
}

// redirectTempDir points os.TempDir at dir for the duration of the test, skipping if this
// platform resolves it some other way. os.TempDir reads TMPDIR on unix and TMP/TEMP on
// Windows, so all three are set and the result is checked rather than assumed.
func redirectTempDir(t *testing.T, dir string) {
	t.Helper()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
	if got := os.TempDir(); got != dir {
		t.Skipf("cannot redirect os.TempDir on %s: got %q, want %q", runtime.GOOS, got, dir)
	}
}

// TestWriteToTempFile_ReportsCreateFailure covers the one failure this function can
// actually hit: the temp directory not being usable. Everything else it guards against is
// either impossible (the filename is generated, never supplied) or not reachable without
// changing the signature to accept a writer.
//
// The contract on that path is what matters to a caller: no path, a wrapped error naming
// the step, and a cleanup that is still safe to defer.
func TestWriteToTempFile_ReportsCreateFailure(t *testing.T) {
	redirectTempDir(t, filepath.Join(t.TempDir(), "does-not-exist"))

	path, cleanup, err := WriteToTempFile([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0"}`))

	require.Error(t, err)
	assert.ErrorContains(t, err, "creating temp file")
	assert.Empty(t, path, "no path may be returned when the file was never created")
	require.NotNil(t, cleanup, "cleanup must be non-nil so a caller can defer it unconditionally")
	assert.NotPanics(t, cleanup)
	assert.NotPanics(t, cleanup, "cleanup must stay safe when called more than once")
}

// TestWriteToTempFile_CreateFailureIsNotMistakenForAnEmptyDocument keeps the two error
// paths distinguishable. Both return an empty path, so a caller telling them apart depends
// on the errors themselves, and ErrEmptyDocument is the sentinel one.
func TestWriteToTempFile_CreateFailureIsNotMistakenForAnEmptyDocument(t *testing.T) {
	redirectTempDir(t, filepath.Join(t.TempDir(), "does-not-exist"))

	_, _, err := WriteToTempFile([]byte("real content"))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrEmptyDocument)

	_, _, emptyErr := WriteToTempFile(nil)
	assert.ErrorIs(t, emptyErr, ErrEmptyDocument)
}

// TestRandomFilename covers the shape the debugging story depends on: a leftover file has
// to be identifiable as this package's, and two calls must not collide.
func TestRandomFilename(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		name := randomFilename()
		assert.True(t, strings.HasPrefix(name, "kubevuln-vexdoc-"), name)
		assert.True(t, strings.HasSuffix(name, ".json"), name)
		// 16 random bytes hex-encoded, between the fixed prefix and suffix.
		assert.Len(t, name, len("kubevuln-vexdoc-")+32+len(".json"), name)
		_, dup := seen[name]
		require.False(t, dup, "duplicate filename %q after %d draws", name, i)
		seen[name] = struct{}{}
	}
}
