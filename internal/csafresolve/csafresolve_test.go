package csafresolve

import (
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadRealAdvisory loads the real, unmodified Red Hat CSAF advisory for
// CVE-2024-3094 (the XZ Utils backdoor) used throughout this test file. It
// is the same document used in the kubevuln#387 (External VEX Ingestion)
// proof of concept's CSAF gap reproduction.
func loadRealAdvisory(t *testing.T) *csaf.Advisory {
	t.Helper()
	adv, err := csaf.LoadAdvisory("testdata/redhat-cve-2024-3094.json")
	require.NoError(t, err, "the real testdata file should load and validate as genuine CSAF")
	return adv
}

// TestResolve_RealAdvisory_AllCompositeIDsResolve is the real end-to-end
// proof: every composite product ID this real advisory's
// known_not_affected list names resolves to a real, correct purl. This
// mirrors exactly what was independently confirmed with a standalone script
// before writing this package (26 of 26 resolved).
func TestResolve_RealAdvisory_AllCompositeIDsResolve(t *testing.T) {
	adv := loadRealAdvisory(t)
	resolver := New(adv.ProductTree)

	require.NotNil(t, adv.Vulnerabilities)
	require.Len(t, adv.Vulnerabilities, 1)
	vuln := adv.Vulnerabilities[0]
	require.NotNil(t, vuln.ProductStatus)
	require.NotNil(t, vuln.ProductStatus.KnownNotAffected)

	compositeIDs := *vuln.ProductStatus.KnownNotAffected
	require.NotEmpty(t, compositeIDs, "sanity check: this advisory should genuinely list affected products")

	resolved := 0
	for _, cid := range compositeIDs {
		purl, err := resolver.Resolve(string(*cid))
		if assert.NoError(t, err, "composite ID %q should resolve", *cid) {
			assert.Contains(t, purl, "pkg:rpm/redhat/", "resolved purl should be a real Red Hat rpm purl, got %q", purl)
			resolved++
		}
	}

	assert.Equal(t, len(compositeIDs), resolved,
		"every composite product ID in this real advisory should resolve to a real purl")
}

// TestResolve_RealAdvisory_KnownXZPurl proves one specific, hand-verified
// resolution: the main xz package itself resolves to exactly the purl
// confirmed by direct inspection of the real document.
func TestResolve_RealAdvisory_KnownXZPurl(t *testing.T) {
	adv := loadRealAdvisory(t)
	resolver := New(adv.ProductTree)

	purl, err := resolver.Resolve("red_hat_enterprise_linux_10:xz")
	require.NoError(t, err)
	assert.Equal(t, "pkg:rpm/redhat/xz", purl)
}

// TestResolve_UnknownCompositeID_ReturnsErrNoRelationship proves a
// composite ID that genuinely does not exist in the advisory is rejected
// with the correct, specific error - not silently returning an empty
// string or the wrong error.
func TestResolve_UnknownCompositeID_ReturnsErrNoRelationship(t *testing.T) {
	adv := loadRealAdvisory(t)
	resolver := New(adv.ProductTree)

	_, err := resolver.Resolve("this_product_id_does_not_exist:anywhere")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoRelationship)
}

// TestResolve_NilProductTree_NeverPanics proves New and Resolve are safe to
// call on a completely empty/nil tree - every call should return
// ErrNoRelationship, not panic.
func TestResolve_NilProductTree_NeverPanics(t *testing.T) {
	resolver := New(nil)

	assert.NotPanics(t, func() {
		_, err := resolver.Resolve("anything")
		assert.ErrorIs(t, err, ErrNoRelationship)
	})
}

// TestResolve_ReferenceWithNoPURL_ReturnsErrNoPURL proves the honest,
// expected case where a relationship exists but its referenced product
// genuinely carries no purl anywhere in the branches tree - this is real,
// valid CSAF, not malformed data, and must be reported with the specific
// ErrNoPURL rather than being confused with a missing relationship.
func TestResolve_ReferenceWithNoPURL_ReturnsErrNoPURL(t *testing.T) {
	trueVal := true
	name := "product_version"
	category := csaf.BranchCategory("product_version")
	relCategory := csaf.RelationshipCategory("default_component_of")

	compositeID := csaf.ProductID("distro:no-purl-package")
	bareRef := csaf.ProductID("no-purl-package")
	distroRef := csaf.ProductID("distro")

	tree := &csaf.ProductTree{
		Branches: csaf.Branches{
			&csaf.Branch{
				Category: &category,
				Name:     &name,
				Product: &csaf.FullProductName{
					Name:      &name,
					ProductID: &bareRef,
					// deliberately no ProductIdentificationHelper at all
				},
			},
		},
		RelationShips: &csaf.Relationships{
			&csaf.Relationship{
				Category: &relCategory,
				FullProductName: &csaf.FullProductName{
					Name:      &name,
					ProductID: &compositeID,
				},
				ProductReference:          &bareRef,
				RelatesToProductReference: &distroRef,
			},
		},
	}
	_ = trueVal // silence unused warning if left over from copy-paste

	resolver := New(tree)
	_, err := resolver.Resolve(string(compositeID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoPURL)
}

// TestResolve_PURLUnderFullProductNames_NotBranches proves the fix for a
// real gap flagged in review: a purl declared under the separate top-level
// product_tree.full_product_names field, rather than nested inside
// product_tree.branches, must still resolve correctly. The original
// hand-rolled tree walk only checked branches, so a document shaped this
// way would silently return ErrNoPURL even though the purl genuinely
// exists in the document - this did not trigger against the bundled real
// Red Hat advisory, which happens to declare everything under branches, so
// the existing tests did not catch it.
func TestResolve_PURLUnderFullProductNames_NotBranches(t *testing.T) {
	category := csaf.RelationshipCategory("default_component_of")
	name := "some-package"
	compositeID := csaf.ProductID("distro:some-package")
	bareRef := csaf.ProductID("some-package")
	distroRef := csaf.ProductID("distro")
	purl := csaf.PURL("pkg:rpm/redhat/some-package")

	tree := &csaf.ProductTree{
		// Deliberately empty Branches - the purl lives only under
		// FullProductNames, proving Resolve does not depend on the
		// branches tree to find it.
		FullProductNames: &csaf.FullProductNames{
			&csaf.FullProductName{
				Name:      &name,
				ProductID: &bareRef,
				ProductIdentificationHelper: &csaf.ProductIdentificationHelper{
					PURL: &purl,
				},
			},
		},
		RelationShips: &csaf.Relationships{
			&csaf.Relationship{
				Category: &category,
				FullProductName: &csaf.FullProductName{
					Name:      &name,
					ProductID: &compositeID,
				},
				ProductReference:          &bareRef,
				RelatesToProductReference: &distroRef,
			},
		},
	}

	resolver := New(tree)
	got, err := resolver.Resolve(string(compositeID))
	require.NoError(t, err, "a purl declared under full_product_names should resolve, not return ErrNoPURL")
	assert.Equal(t, "pkg:rpm/redhat/some-package", got)
}
