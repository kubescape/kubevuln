// Package vexvalidate checks that a fetched OpenVEX document is genuinely
// real and meaningful, not just syntactically valid JSON.
//
// github.com/openvex/go-vex's Load/Parse functions only decode JSON into the
// VEX struct - they perform no validation of their own, so a document as
// empty as {} is returned as a "successfully parsed" document with no error.
// Nothing in kubevuln has needed to notice this so far, since it has only
// ever read VEX documents it wrote itself, which are always well-formed.
// The External VEX Ingestion project (kubevuln#387) changes that: it fetches
// a vendor's VEX feed from a URL kubevuln does not control, so a
// misconfigured or broken feed (a login page, an error page, a truncated
// file) needs to be caught here, before it is ever persisted - not
// discovered later by whatever eventually tries to consume it. See #878.
package vexvalidate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
)

// Errors returned by Validate. Each identifies which specific requirement a
// document failed, so a caller (or a test) can distinguish a malformed
// context from an empty document from an invalid statement.
var (
	// ErrInvalidContext is returned when the document's @context is empty or
	// does not identify it as an OpenVEX document.
	ErrInvalidContext = errors.New("vexvalidate: document has no valid @context")

	// ErrNoStatements is returned when the document has zero statements. A
	// VEX document that asserts nothing is not useful to anything that
	// would consume it.
	ErrNoStatements = errors.New("vexvalidate: document has no statements")

	// ErrInvalidStatement is returned when a statement fails go-vex's own,
	// stricter Statement.Validate() - an invalid status, or a status paired
	// with fields that status does not allow (e.g. not_affected with no
	// justification or impact statement, or affected with no action
	// statement).
	ErrInvalidStatement = errors.New("vexvalidate: statement is invalid")

	// ErrNoProducts is returned when a statement lists zero products.
	ErrNoProducts = errors.New("vexvalidate: statement has no products")

	// ErrEmptyProduct is returned when a statement's product identifies
	// nothing at all - no @id, no hashes, no identifiers. go-vex's own
	// Component type makes ID optional (it can also be identified by hashes
	// or identifiers instead), so an empty {} still decodes successfully;
	// only a product with none of the three says nothing about what it
	// actually is.
	ErrEmptyProduct = errors.New("vexvalidate: statement has a product that identifies nothing")
)

// openVEXContextPrefix is the real OpenVEX namespace URI. The spec allows a
// versioned form (e.g. "https://openvex.dev/ns/v0.2.0") alongside the bare
// one, so a document is checked against this prefix, not exact equality.
const openVEXContextPrefix = "https://openvex.dev/ns"

// hasValidContext reports whether context is the bare OpenVEX namespace URI
// or a versioned form of it. A plain strings.HasPrefix check alone would
// wrongly accept "https://openvex.dev/nsfoobar.evil.com", since that string
// does genuinely start with the prefix - so whatever immediately follows
// the prefix must be either nothing (the bare form) or a "/" (a versioned
// form), never any other character.
func hasValidContext(context string) bool {
	if !strings.HasPrefix(context, openVEXContextPrefix) {
		return false
	}
	rest := context[len(openVEXContextPrefix):]
	return rest == "" || strings.HasPrefix(rest, "/")
}

// productIsEmpty reports whether p identifies nothing at all. A Product's ID
// is optional in go-vex's own Component type, since a product can instead be
// identified by Hashes or Identifiers - so ID alone being unset does not
// make a product empty, but having none of the three does.
func productIsEmpty(p vex.Product) bool {
	return p.ID == "" && len(p.Hashes) == 0 && len(p.Identifiers) == 0
}

// Validate parses data as an OpenVEX document and checks it is genuinely
// real: a valid @context, at least one statement, and every statement
// passing go-vex's own, stricter Statement.Validate() with at least one
// product that actually identifies something.
//
// Validate deliberately reuses go-vex's own Statement.Validate() rather than
// re-implementing a subset of its rules, so this package cannot drift out of
// sync with what the library itself considers a well-formed statement.
func Validate(data []byte) error {
	doc, err := vex.Parse(data)
	if err != nil {
		return fmt.Errorf("vexvalidate: parsing document: %w", err)
	}

	if !hasValidContext(doc.Context) {
		return ErrInvalidContext
	}

	if len(doc.Statements) == 0 {
		return ErrNoStatements
	}

	for i := range doc.Statements {
		s := &doc.Statements[i]

		if err := s.Validate(); err != nil {
			return fmt.Errorf("%w: statement %d: %w", ErrInvalidStatement, i, err)
		}

		if len(s.Products) == 0 {
			return fmt.Errorf("%w: statement %d", ErrNoProducts, i)
		}

		for j, p := range s.Products {
			if productIsEmpty(p) {
				return fmt.Errorf("%w: statement %d, product %d", ErrEmptyProduct, i, j)
			}
		}
	}

	return nil
}
