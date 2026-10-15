// Package testfixture loads JSON fixtures for tests.
//
// It exists so the same loader is used everywhere. Before it, three packages
// had their own: two of them returned a zero value when the file was missing
// or did not parse, so renaming a fixture turned its tests into ones that
// passed while asserting against an empty document.
package testfixture

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads path and unmarshals it into a new T.
//
// It panics rather than returning an error. Every caller is a test, and a
// fixture that cannot be read or parsed means the test is no longer exercising
// what it was written to exercise; failing loudly at that point is the whole
// point of the helper.
func Load[T any](path string) *T {
	var value *T
	if err := json.Unmarshal(Bytes(path), &value); err != nil {
		panic(fmt.Sprintf("testfixture: parsing %s: %v", path, err))
	}
	if value == nil {
		// A fixture holding the literal "null" unmarshals into a nil pointer
		// without error, which would hand the caller something to dereference.
		panic(fmt.Sprintf("testfixture: %s unmarshals to null", path))
	}

	return value
}

// Bytes reads path and returns its contents, for tests that assert on the raw
// JSON rather than a decoded value.
func Bytes(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("testfixture: reading %s: %v", path, err))
	}

	return b
}
