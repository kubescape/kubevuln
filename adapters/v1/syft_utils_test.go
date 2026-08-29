package v1

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCleanDigestAlgorithmName tests the normalization of various hash algorithm names including hyphens and underscores.
func TestCleanDigestAlgorithmName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "uppercase with hyphen", input: "SHA-256", want: "sha256"},
		{name: "already lowercase, no hyphen", input: "md5", want: "md5"},
		{name: "mixed case with hyphen", input: "Sha-1", want: "sha1"},
		{name: "multiple hyphens", input: "SHA-512-256", want: "sha512256"},
		{name: "lowercase with underscore", input: "sha_256", want: "sha256"},
		{name: "uppercase with underscore", input: "SHA_512", want: "sha512"},
		{name: "mixed hyphens and underscores", input: "Sha_512-256", want: "sha512256"},
		{name: "empty string", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanDigestAlgorithmName(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestHashers tests resolving hash algorithm names to their crypto.Hash types.
func TestHashers(t *testing.T) {
	t.Run("supported algorithms are resolved correctly", func(t *testing.T) {
		got, err := Hashers("sha-256", "MD5", "Sha-1")
		assert.NoError(t, err)
		assert.Equal(t, []crypto.Hash{crypto.SHA256, crypto.MD5, crypto.SHA1}, got)
	})

	t.Run("underscore delimited algorithms are resolved correctly", func(t *testing.T) {
		got, err := Hashers("sha_256", "SHA_512", "sha_384", "sha_224", "sha_1")
		assert.NoError(t, err)
		assert.Equal(t, []crypto.Hash{crypto.SHA256, crypto.SHA512, crypto.SHA384, crypto.SHA224, crypto.SHA1}, got)
	})

	t.Run("no names returns empty result", func(t *testing.T) {
		got, err := Hashers()
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("unsupported algorithm returns an error", func(t *testing.T) {
		got, err := Hashers("sha-256", "not-a-real-hash")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "unsupported hash algorithm: not-a-real-hash")
	})
}
