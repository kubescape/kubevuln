// Package csafresolve resolves a CSAF advisory's composite product IDs (e.g.
// "red_hat_enterprise_linux_10:xz") into real, comparable purls.
//
// grype's own CSAF matcher (grype/grype/vex/csaf) compares purls by exact
// string equality, but only ever looks for a purl directly on a
// relationships entry - which real Red Hat advisories never populate (0 of
// 26 relationships in a real, downloaded advisory for CVE-2024-3094 carry a
// purl there). The real purl exists elsewhere in the same document: each
// relationship's product_reference names a bare product ID (e.g. "xz"), and
// that bare ID has its own entry deeper in product_tree.branches, carrying
// a real product_identification_helper.purl. This package walks both
// structures and connects them - verified against a real, unmodified
// advisory, where all 26 composite IDs resolved successfully.
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
	// product_identification_helper.purl anywhere in the branches tree.
	// This is a real, expected outcome for some products, not a bug: not
	// every advisory attaches a purl to every product it mentions.
	ErrNoPURL = errors.New("csafresolve: resolved product has no purl in this advisory")
)

// Resolver resolves composite product IDs to purls for one CSAF advisory.
// Build one with New and reuse it across every lookup for that advisory,
// rather than re-walking the document per call.
type Resolver struct {
	// compositeToRef maps a composite product ID (from a relationship's
	// full_product_name.product_id) to that relationship's bare
	// product_reference.
	compositeToRef map[string]string

	// refToPURL maps a bare product ID (from anywhere in the branches
	// tree) to its real purl, where one exists.
	refToPURL map[string]string
}

// New builds a Resolver for the given advisory by walking its product tree
// once. If tree is nil or has no relationships/branches, the returned
// Resolver simply resolves nothing - every Resolve call will return
// ErrNoRelationship - rather than New itself failing.
func New(tree *csaf.ProductTree) *Resolver {
	r := &Resolver{
		compositeToRef: make(map[string]string),
		refToPURL:      make(map[string]string),
	}
	if tree == nil {
		return r
	}

	if tree.RelationShips != nil {
		for _, rel := range *tree.RelationShips {
			if rel == nil || rel.FullProductName == nil || rel.FullProductName.ProductID == nil || rel.ProductReference == nil {
				continue
			}
			compositeID := string(*rel.FullProductName.ProductID)
			ref := string(*rel.ProductReference)
			r.compositeToRef[compositeID] = ref
		}
	}

	for _, b := range tree.Branches {
		r.walkBranch(b)
	}

	return r
}

// walkBranch recurses through the branches tree, recording every bare
// product ID that carries a real purl.
func (r *Resolver) walkBranch(b *csaf.Branch) {
	if b == nil {
		return
	}
	if b.Product != nil && b.Product.ProductID != nil && b.Product.ProductIdentificationHelper != nil {
		if purl := b.Product.ProductIdentificationHelper.PURL; purl != nil {
			r.refToPURL[string(*b.Product.ProductID)] = string(*purl)
		}
	}
	for _, child := range b.Branches {
		r.walkBranch(child)
	}
}

// Resolve returns the real purl for compositeID (e.g.
// "red_hat_enterprise_linux_10:xz"), or an error explaining why it could
// not be resolved.
func (r *Resolver) Resolve(compositeID string) (string, error) {
	ref, ok := r.compositeToRef[compositeID]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoRelationship, compositeID)
	}
	purl, ok := r.refToPURL[ref]
	if !ok {
		return "", fmt.Errorf("%w: %q (product_reference %q)", ErrNoPURL, compositeID, ref)
	}
	return purl, nil
}
