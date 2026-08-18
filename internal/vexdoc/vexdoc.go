// Package vexdoc provides a safe way to write a VEX document to a temporary
// file on disk. grype's own vex.Processor (grype/vex) only accepts real file
// paths - it has no way to accept an in-memory document - so anything that
// wants to hand a fetched VEX document to grype's matcher must first write
// it to disk safely. This package is that safe primitive: nothing in this
// repo currently calls grype's VEX matching (confirmed by a repo-wide search
// for ApplyVEX/vex.NewProcessor/vex.Processor turning up nothing outside
// grype's own library code), so wiring VEX matching in is separate, later
// work - this package only closes the concrete blocker anyone doing that
// would hit first.
package vexdoc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Errors returned by WriteToTempFile.
var (
	// ErrEmptyDocument is returned when data is empty. An empty file is
	// never useful to a VEX processor and is more likely a caller bug
	// (e.g. an unchecked failed fetch) than a genuine empty document.
	ErrEmptyDocument = errors.New("vexdoc: document is empty")
)

// WriteToTempFile safely writes data (a fetched VEX document) to a new,
// uniquely-named file inside the OS's temp directory, and returns its path
// along with a cleanup function that removes it.
//
// Safety properties:
//   - The filename is derived from random bytes, not from any
//     caller-supplied or document-derived value, so two different documents
//     can never collide on the same path and one write can never overwrite
//     another.
//   - The file is created with 0o600 permissions (owner read/write only),
//     not the more permissive default, since a VEX document's contents
//     (which images/packages a vendor has commented on) are not meant to be
//     world-readable.
//   - The file is always created inside os.TempDir() - never a
//     caller-supplied directory - so this function cannot be used to write
//     to an arbitrary, attacker-chosen location.
//   - The returned cleanup function is always safe to call, even if writing
//     failed partway through; callers should defer it immediately after
//     checking err, matching the standard os.CreateTemp pattern.
//
// This function does not itself enforce a maximum document size. It is not
// responsible for fetching data over the network - a caller pulling a VEX
// document from an external source should bound its size before it ever
// reaches this function (see internal/safefetch.Fetcher.MaxBytes for the
// existing pattern this repo already uses for that).
func WriteToTempFile(data []byte) (path string, cleanup func(), err error) {
	noop := func() {}

	if len(data) == 0 {
		return "", noop, ErrEmptyDocument
	}

	name, err := randomFilename()
	if err != nil {
		return "", noop, fmt.Errorf("vexdoc: generating a random filename: %w", err)
	}

	path = filepath.Join(os.TempDir(), name)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", noop, fmt.Errorf("vexdoc: creating temp file: %w", err)
	}

	cleanup = func() {
		_ = os.Remove(path)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return "", noop, fmt.Errorf("vexdoc: writing document: %w", err)
	}

	if err := f.Close(); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("vexdoc: closing temp file: %w", err)
	}

	return path, cleanup, nil
}

// randomFilename returns an unpredictable filename with a recognizable
// prefix and extension, so a leaked or leftover file is identifiable as
// belonging to this package during debugging.
func randomFilename() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("kubevuln-vexdoc-%s.json", hex.EncodeToString(b)), nil
}
