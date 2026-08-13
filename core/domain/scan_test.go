package domain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanError_Error(t *testing.T) {
	inner := errors.New("boom")
	scanErr := &ScanError{Reason: "some-reason", Err: inner}

	assert.Equal(t, "boom", scanErr.Error())
}

func TestScanError_Unwrap(t *testing.T) {
	inner := errors.New("boom")
	scanErr := &ScanError{Reason: "some-reason", Err: inner}

	assert.Equal(t, inner, scanErr.Unwrap())
}

func TestScanError_ErrorsIs(t *testing.T) {
	// ScanError's own doc comment promises that wrapping a sentinel error keeps
	// existing errors.Is-based checks working exactly as before wrapping.
	var err error = &ScanError{Reason: "too-many-requests", Err: ErrTooManyRequests}

	assert.True(t, errors.Is(err, ErrTooManyRequests))
	assert.False(t, errors.Is(err, ErrMissingSBOM))
}

func TestScanError_ErrorsAs(t *testing.T) {
	// Callers up the stack recover the Reason via errors.As without re-deriving
	// it from the error string, per ScanError's doc comment.
	var err error = &ScanError{Reason: "outdated-sbom", Err: ErrOutdatedSBOM}

	var scanErr *ScanError
	ok := errors.As(err, &scanErr)

	assert.True(t, ok)
	assert.Equal(t, "outdated-sbom", scanErr.Reason)
}

func TestScanError_WrappedInFmtErrorf(t *testing.T) {
	// A ScanError wrapped further (e.g. via fmt.Errorf("%w", ...) somewhere up
	// the call chain) must still be recoverable via errors.As/errors.Is.
	scanErr := &ScanError{Reason: "incomplete-sbom", Err: ErrIncompleteSBOM}
	wrapped := errors.Join(errors.New("context"), scanErr)

	var got *ScanError
	assert.True(t, errors.As(wrapped, &got))
	assert.Equal(t, "incomplete-sbom", got.Reason)
	assert.True(t, errors.Is(wrapped, ErrIncompleteSBOM))
}
