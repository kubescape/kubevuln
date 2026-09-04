package vexvalidate

import (
	"errors"
	"testing"
)

const validDocument = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.com/vex-1",
	"author": "test",
	"timestamp": "2026-01-01T00:00:00Z",
	"version": 1,
	"statements": [
		{
			"vulnerability": {"name": "CVE-2024-0001"},
			"products": [{"@id": "pkg:oci/test-image"}],
			"status": "not_affected",
			"justification": "vulnerable_code_not_present"
		}
	]
}`

func TestValidate_RealDocument_Passes(t *testing.T) {
	if err := Validate([]byte(validDocument)); err != nil {
		t.Fatalf("expected a real, well-formed document to pass, got: %v", err)
	}
}

func TestValidate_MultipleValidStatements_Passes(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"author": "test",
		"statements": [
			{"vulnerability": {"name": "CVE-2024-0001"}, "products": [{"@id": "pkg:oci/a"}], "status": "not_affected", "justification": "vulnerable_code_not_present"},
			{"vulnerability": {"name": "CVE-2024-0002"}, "products": [{"@id": "pkg:oci/b"}], "status": "fixed"}
		]
	}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("expected multiple valid statements to pass, got: %v", err)
	}
}

func TestValidate_BareContext_Passes(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}]}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("expected the bare, unversioned context to be valid, got: %v", err)
	}
}

func TestValidate_ProductIdentifiedByHashOnly_Passes(t *testing.T) {
	// A product with no @id but a real hash still identifies something real -
	// go-vex's own Component type allows this, so Validate must too.
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"hashes": {"sha256": "abc123"}}], "status": "fixed"}]}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("expected a hash-identified product to be valid, got: %v", err)
	}
}

func TestValidate_ProductIdentifiedByIdentifierOnly_Passes(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"identifiers": {"purl": "pkg:oci/a"}}], "status": "fixed"}]}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("expected an identifier-identified product to be valid, got: %v", err)
	}
}

func TestValidate_NilInput_Rejected(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Fatal("expected nil input to be rejected")
	}
}

func TestValidate_EmptyInput_Rejected(t *testing.T) {
	if err := Validate([]byte{}); err == nil {
		t.Fatal("expected empty input to be rejected")
	}
}

func TestValidate_InvalidJSON_Rejected(t *testing.T) {
	if err := Validate([]byte(`not json at all`)); err == nil {
		t.Fatal("expected invalid JSON to be rejected")
	}
}

func TestValidate_TruncatedJSON_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vuln`
	if err := Validate([]byte(doc)); err == nil {
		t.Fatal("expected truncated JSON to be rejected")
	}
}

func TestValidate_EmptyDocument_RejectedForContext(t *testing.T) {
	err := Validate([]byte(`{}`))
	if !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("expected ErrInvalidContext for an empty document, got: %v", err)
	}
}

func TestValidate_MissingContext_Rejected(t *testing.T) {
	doc := `{"author": "test", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("expected ErrInvalidContext, got: %v", err)
	}
}

func TestValidate_WrongContext_Rejected(t *testing.T) {
	doc := `{"@context": "https://example.com/not-openvex", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("expected ErrInvalidContext for a non-OpenVEX context, got: %v", err)
	}
}

func TestValidate_LookalikeContext_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/nsfoobar.evil.com", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("expected ErrInvalidContext for a lookalike context, got: %v", err)
	}
}

func TestValidate_NoStatements_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "author": "test", "statements": []}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoStatements) {
		t.Fatalf("expected ErrNoStatements, got: %v", err)
	}
}

func TestValidate_MissingStatementsField_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "author": "test"}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoStatements) {
		t.Fatalf("expected ErrNoStatements when the field is absent entirely, got: %v", err)
	}
}

func TestValidate_NullStatementsField_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": null}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoStatements) {
		t.Fatalf("expected ErrNoStatements for an explicit null, got: %v", err)
	}
}

func TestValidate_InvalidStatus_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "totally_fine_probably"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("expected ErrInvalidStatement, got: %v", err)
	}
}

func TestValidate_EmptyStatus_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}]}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("expected ErrInvalidStatement for a missing status, got: %v", err)
	}
}

func TestValidate_NotAffectedWithNoJustificationOrImpact_Rejected(t *testing.T) {
	// This is exactly matthyx's second point: go-vex's own Statement.Validate()
	// requires a justification or impact statement for not_affected, which our
	// old plain Status.Valid() check never caught.
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "not_affected"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("expected ErrInvalidStatement for not_affected with no justification/impact, got: %v", err)
	}
}

func TestValidate_AffectedWithNoActionStatement_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "affected"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("expected ErrInvalidStatement for affected with no action statement, got: %v", err)
	}
}

func TestValidate_AffectedWithActionStatement_Passes(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "affected", "action_statement": "update to 1.2.4"}]}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("expected affected with an action statement to be valid, got: %v", err)
	}
}

func TestValidate_FixedWithIrrelevantFieldSet_Rejected(t *testing.T) {
	// go-vex's Statement.Validate() also rejects the opposite mistake: a
	// field set on a status that must not carry it.
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed", "justification": "vulnerable_code_not_present"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("expected ErrInvalidStatement for fixed with a justification set, got: %v", err)
	}
}

func TestValidate_NoProducts_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoProducts) {
		t.Fatalf("expected ErrNoProducts, got: %v", err)
	}
}

func TestValidate_MissingProductsField_Rejected(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoProducts) {
		t.Fatalf("expected ErrNoProducts when the field is absent entirely, got: %v", err)
	}
}

func TestValidate_EmptyPlaceholderProduct_Rejected(t *testing.T) {
	// This is matthyx's first point: a product with no @id, no hashes, and no
	// identifiers passed the old check, since it only looked at slice length.
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{}], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrEmptyProduct) {
		t.Fatalf("expected ErrEmptyProduct for a placeholder product, got: %v", err)
	}
}

func TestValidate_OneRealProductAmongEmptyOnes_Rejected(t *testing.T) {
	// Every product in the list must identify something - one real product
	// alongside a placeholder must not let the placeholder slide through.
	doc := `{"@context": "https://openvex.dev/ns", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}, {}], "status": "fixed"}]}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrEmptyProduct) {
		t.Fatalf("expected ErrEmptyProduct when any product in the list is a placeholder, got: %v", err)
	}
}

func TestValidate_SecondStatementInvalid_Rejected(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": [
			{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"},
			{"vulnerability": {"name": "CVE-2"}, "products": [], "status": "fixed"}
		]
	}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoProducts) {
		t.Fatalf("expected ErrNoProducts for the second, broken statement, got: %v", err)
	}
}

func TestValidate_FirstStatementInvalid_Rejected(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": [
			{"vulnerability": {"name": "CVE-1"}, "products": [], "status": "fixed"},
			{"vulnerability": {"name": "CVE-2"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}
		]
	}`
	err := Validate([]byte(doc))
	if !errors.Is(err, ErrNoProducts) {
		t.Fatalf("expected ErrNoProducts for the first, broken statement, got: %v", err)
	}
}

func TestValidate_AllOpenVEXStatuses_WithRequiredFields_Accepted(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"not_affected", `{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "not_affected", "justification": "vulnerable_code_not_present"}`},
		{"affected", `{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "affected", "action_statement": "update to 1.2.4"}`},
		{"fixed", `{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "fixed"}`},
		{"under_investigation", `{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/a"}], "status": "under_investigation"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := `{"@context": "https://openvex.dev/ns", "statements": [` + c.doc + `]}`
			if err := Validate([]byte(doc)); err != nil {
				t.Fatalf("expected status %q with its required fields to be valid, got: %v", c.name, err)
			}
		})
	}
}

// A statement that never says which vulnerability it is about passes every other check:
// go-vex's Statement.Validate checks the status and the fields each status may carry, but
// not this. Matching keys on the vulnerability name, so an unnamed statement keys on the
// empty string and collides with every other unnamed one.
func TestValidate_StatementWithoutVulnerability_Fails(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"status": "fixed", "products": [{"@id": "pkg:oci/x"}]}]}`
	if err := Validate([]byte(doc)); !errors.Is(err, ErrNoVulnerability) {
		t.Fatalf("expected ErrNoVulnerability, got: %v", err)
	}
}

func TestValidate_VulnerabilityIdentifiedByEitherField(t *testing.T) {
	byName := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-2024-0001"}, "products": [{"@id": "pkg:oci/x"}], "status": "fixed"}]}`
	if err := Validate([]byte(byName)); err != nil {
		t.Fatalf("a name identifies the vulnerability, got: %v", err)
	}

	byID := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"@id": "https://example.test/CVE-2024-0001"}, "products": [{"@id": "pkg:oci/x"}], "status": "fixed"}]}`
	if err := Validate([]byte(byID)); err != nil {
		t.Fatalf("an @id alone identifies the vulnerability, got: %v", err)
	}

	whitespace := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "   "}, "products": [{"@id": "pkg:oci/x"}], "status": "fixed"}]}`
	if err := Validate([]byte(whitespace)); !errors.Is(err, ErrNoVulnerability) {
		t.Fatalf("expected ErrNoVulnerability for a whitespace-only name, got: %v", err)
	}
}

// The same emptiness test a product already gets, one level down. Subcomponents are what
// scope a statement to a package, which is the granularity suppression matches on.
func TestValidate_EmptySubcomponent_Fails(t *testing.T) {
	only := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/x", "subcomponents": [{}]}], "status": "fixed"}]}`
	if err := Validate([]byte(only)); !errors.Is(err, ErrEmptySubcomponent) {
		t.Fatalf("expected ErrEmptySubcomponent, got: %v", err)
	}

	second := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/x", "subcomponents": [{"@id": "pkg:deb/a"}, {}]}], "status": "fixed"}]}`
	if err := Validate([]byte(second)); !errors.Is(err, ErrEmptySubcomponent) {
		t.Fatalf("a later empty subcomponent counts too, got: %v", err)
	}
}

func TestValidate_PopulatedSubcomponents_Pass(t *testing.T) {
	byID := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/x", "subcomponents": [{"@id": "pkg:deb/a"}, {"@id": "pkg:deb/b"}]}], "status": "fixed"}]}`
	if err := Validate([]byte(byID)); err != nil {
		t.Fatalf("populated subcomponents should pass, got: %v", err)
	}

	byHash := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/x", "subcomponents": [{"hashes": {"sha256": "abc"}}]}], "status": "fixed"}]}`
	if err := Validate([]byte(byHash)); err != nil {
		t.Fatalf("hashes identify a subcomponent, same as a product, got: %v", err)
	}
}

// No subcomponents at all is product scope, which is legitimate and must stay so.
func TestValidate_NoSubcomponents_Passes(t *testing.T) {
	doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:oci/x"}], "status": "fixed"}]}`
	if err := Validate([]byte(doc)); err != nil {
		t.Fatalf("product-scope statements must still pass, got: %v", err)
	}
}
