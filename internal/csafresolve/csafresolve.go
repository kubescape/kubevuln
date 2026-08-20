// Package csafresolve resolves a CSAF advisory's composite product IDs (e.g.
// "red_hat_enterprise_linux_10:xz") into real, comparable purls.
//
// grype's own CSAF matcher (grype/grype/vex/csaf) compares purls by exact
// string equality, but only ever looks for a purl directly on a
// relationships entry - which real Red Hat advisories never populate (0 of
// 26 relationships in a real, downloaded advisory for CVE-2024-3094 carry a
// purl there). The real purl exists elsewhere in the same document: each
// relationship's product_reference names a bare product ID (e.g. "xz"), and
// that bare ID has its own real entry with a purl - either nested under
// product_tree.branches, or declared directly under the separate top-level
// product_tree.full_product_names field. This package resolves the
// composite ID down to that bare reference, then reuses gocsaf/csaf's own
// ProductTree.CollectProductIdentificationHelpers to find its purl,
// wherever in the document it is actually declared - rather than
// hand-walking the tree ourselves and risking missing a location the
// upstream package already knows about.
//
// This does not fix grype's matcher itself - it is a standalone translator
// that anything wiring CSAF matching into a real scan can use to get a real
// purl for a composite product ID before comparing it.
package csafresolve

import (
	"errors"
	"fmt"

	"github.com/gocsaf/csaf/v3/csaf"
)

// Errors returned by Resolve.
var (
	// ErrNoRelationship is returned when compositeID does not match any
	// relationship's full_product_name.product_id in the advisory.
	ErrNoRelationship = errors.New("csafresolve: no relationship found for composite product ID")

	// ErrNoPURL is returned when compositeID resolves to a real
	// product_reference, but that reference has no
	// product_identification_helper.purl anywhere in the document. This
	// is a real, expected outcome for some products, not a bug: not
	// every advisory attaches a purl to every product it mentions.
	ErrNoPURL = errors.New("csafresolve: resolved product has no purl in this advisory")
)

// Resolver resolves composite product IDs to purls for one CSAF advisory.
// Build one with New and reuse it across every lookup for that advisory.
type Resolver struct {
	tree *csaf.ProductTree

	// compositeToRef maps a composite product ID (from a relationship's
	// full_product_name.product_id) to that relationship's bare
	// product_reference. Built once in New; the purl lookup itself is
	// done lazily per Resolve call via the upstream package's own
	// tree-walking helper, so this resolver never needs to duplicate
	// that logic or risk missing a location it doesn't know about.
	compositeToRef map[string]string
}

// New builds a Resolver for the given advisory. If tree is nil or has no
// relationships, the returned Resolver simply resolves nothing - every
// Resolve call will return ErrNoRelationship - rather than New itself
// failing.
func New(tree *csaf.ProductTree) *Resolver {
	r := &Resolver{
		tree:           tree,
		compositeToRef: make(map[string]string),
	}
	if tree == nil || tree.RelationShips == nil {
		return r
	}

	for _, rel := range *tree.RelationShips {
		if rel == nil || rel.FullProductName == nil || rel.FullProductName.ProductID == nil || rel.ProductReference == nil {
			continue
		}
		compositeID := string(*rel.FullProductName.ProductID)
		ref := string(*rel.ProductReference)
		r.compositeToRef[compositeID] = ref
	}

	return r
}

// Resolve returns the real purl for compositeID (e.g.
// "red_hat_enterprise_linux_10:xz"), or an error explaining why it could
// not be resolved.
func (r *Resolver) Resolve(compositeID string) (string, error) {
	ref, ok := r.compositeToRef[compositeID]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoRelationship, compositeID)
	}

	// CollectProductIdentificationHelpers checks full_product_names,
	// branches (recursively), and relationships - a strictly more
	// complete search than hand-walking just the branches tree.
	helpers := r.tree.CollectProductIdentificationHelpers(csaf.ProductID(ref))
	for _, h := range helpers {
		if h != nil && h.PURL != nil {
			return string(*h.PURL), nil
		}
	}

	return "", fmt.Errorf("%w: %q (product_reference %q)", ErrNoPURL, compositeID, ref)
}
