package v1

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashers(t *testing.T) {
	hashers, err := Hashers("sha256", "sha-512")
	require.NoError(t, err)
	assert.Equal(t, []crypto.Hash{crypto.SHA256, crypto.SHA512}, hashers)

	_, err = Hashers("unsupported")
	assert.Error(t, err)
}

func TestCleanDigestAlgorithmName(t *testing.T) {
	assert.Equal(t, "sha256", CleanDigestAlgorithmName("SHA-256"))
	assert.Equal(t, "sha512", CleanDigestAlgorithmName("sha_512"))
}

func TestNormalizeLicenses(t *testing.T) {
	licenses := []string{" MIT ", "", "  ", "Apache-2.0"}
	expected := []string{"MIT", "Apache-2.0"}
	assert.Equal(t, expected, NormalizeLicenses(licenses))
}
