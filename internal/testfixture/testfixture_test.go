package testfixture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sample struct {
	Name string `json:"name"`
}

func write(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	return path
}

func TestLoad(t *testing.T) {
	got := Load[sample](write(t, `{"name":"nginx"}`))
	require.NotNil(t, got)
	assert.Equal(t, "nginx", got.Name)
}

// The behaviour this package exists for: a fixture that is missing, malformed or
// null must stop the test rather than hand back an empty value it would assert
// against.
func TestLoad_FailsLoudly(t *testing.T) {
	tests := []struct {
		name string
		path func() string
	}{
		{
			name: "missing file",
			path: func() string { return filepath.Join(t.TempDir(), "does-not-exist.json") },
		},
		{
			name: "malformed json",
			path: func() string { return write(t, `{"name":`) },
		},
		{
			name: "literal null",
			path: func() string { return write(t, `null`) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Panics(t, func() { _ = Load[sample](tt.path()) })
		})
	}
}

func TestBytes(t *testing.T) {
	assert.Equal(t, `{"name":"nginx"}`, string(Bytes(write(t, `{"name":"nginx"}`))))
	assert.Panics(t, func() { _ = Bytes(filepath.Join(t.TempDir(), "nope.json")) })
}
