package v1

import (
	"crypto"
	"fmt"
	"strings"
)

// supportedHashAlgorithms returns the list of hash algorithms supported by Syft.
func supportedHashAlgorithms() []crypto.Hash {
	return []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}
}

// Hashers converts algorithm name strings into their corresponding crypto.Hash objects.
func Hashers(names ...string) ([]crypto.Hash, error) {
	hashByName := make(map[string]crypto.Hash)
	for _, h := range supportedHashAlgorithms() {
		hashByName[CleanDigestAlgorithmName(h.String())] = h
	}

	var hashers []crypto.Hash
	for _, hashStr := range names {
		hashObj, ok := hashByName[CleanDigestAlgorithmName(hashStr)]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashers = append(hashers, hashObj)
	}
	return hashers, nil
}

// CleanDigestAlgorithmName normalizes a hash algorithm name by lowercasing and stripping hyphens and underscores.
func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	r := strings.NewReplacer("-", "", "_", "")
	return r.Replace(lower)
}
