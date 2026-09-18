package vex

import "testing"

func TestParseValidDocument(t *testing.T) {
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"id": "https://example.com/vex/1",
		"author": "kubescape",
		"timestamp": "2026-09-15T10:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {
					"id": "CVE-2024-0001"
				},
				"products": [
					{
						"id": "pkg:oci/example@sha256:abc"
					}
				],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present"
			}
		]
	}`)

	document, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if document.ID != "https://example.com/vex/1" {
		t.Fatalf("unexpected document ID: %s", document.ID)
	}

	if len(document.Statements) != 1 {
		t.Fatalf("expected one statement, got %d", len(document.Statements))
	}
}

func TestParseRejectsEmptyDocument(t *testing.T) {
	_, err := Parse([]byte("   "))

	if err == nil {
		t.Fatal("expected empty document error")
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	_, err := Parse([]byte(`{"id":`))

	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestValidateRejectsNilDocument(t *testing.T) {
	err := Validate(nil)

	if err == nil {
		t.Fatal("expected nil document error")
	}
}

func TestValidateRejectsMissingContext(t *testing.T) {
	document := validDocument()
	document.Context = ""

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing context error")
	}
}

func TestValidateRejectsInvalidContext(t *testing.T) {
	document := validDocument()
	document.Context = "invalid-context"

	err := Validate(document)

	if err == nil {
		t.Fatal("expected invalid context error")
	}
}

func TestValidateRejectsMissingDocumentID(t *testing.T) {
	document := validDocument()
	document.ID = ""

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing document ID error")
	}
}

func TestValidateRejectsInvalidDocumentID(t *testing.T) {
	document := validDocument()
	document.ID = "invalid-document-id"

	err := Validate(document)

	if err == nil {
		t.Fatal("expected invalid document ID error")
	}
}

func TestValidateRejectsMissingAuthor(t *testing.T) {
	document := validDocument()
	document.Author = ""

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing author error")
	}
}

func TestValidateRejectsInvalidTimestamp(t *testing.T) {
	document := validDocument()
	document.Timestamp = "not-a-timestamp"

	err := Validate(document)

	if err == nil {
		t.Fatal("expected invalid timestamp error")
	}
}

func TestValidateRejectsInvalidVersion(t *testing.T) {
	document := validDocument()
	document.Version = 0

	err := Validate(document)

	if err == nil {
		t.Fatal("expected invalid version error")
	}
}

func TestValidateRejectsMissingStatements(t *testing.T) {
	document := validDocument()
	document.Statements = nil

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing statements error")
	}
}

func TestValidateRejectsMissingVulnerabilityID(t *testing.T) {
	document := validDocument()
	document.Statements[0].Vulnerability.ID = ""

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing vulnerability ID error")
	}
}

func TestValidateRejectsMissingProducts(t *testing.T) {
	document := validDocument()
	document.Statements[0].Products = nil

	err := Validate(document)

	if err == nil {
		t.Fatal("expected missing products error")
	}
}

func TestValidateRejectsEmptyProductID(t *testing.T) {
	document := validDocument()
	document.Statements[0].Products[0].ID = ""

	err := Validate(document)

	if err == nil {
		t.Fatal("expected empty product ID error")
	}
}

func TestValidateRejectsUnsupportedStatus(t *testing.T) {
	document := validDocument()
	document.Statements[0].Status = "unknown_status"

	err := Validate(document)

	if err == nil {
		t.Fatal("expected unsupported status error")
	}
}

func TestValidateAcceptsSupportedStatuses(t *testing.T) {
	statuses := []string{
		StatusNotAffected,
		StatusAffected,
		StatusFixed,
		StatusUnderInvestigation,
	}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			document := validDocument()
			document.Statements[0].Status = status

			if err := Validate(document); err != nil {
				t.Fatalf("expected status %q to be valid, got error: %v", status, err)
			}
		})
	}
}

func validDocument() *Document {
	return &Document{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        "https://example.com/vex/1",
		Author:    "kubescape",
		Timestamp: "2026-09-15T10:00:00Z",
		Version:   1,
		Statements: []Statement{
			{
				Vulnerability: Vulnerability{
					ID: "CVE-2024-0001",
				},
				Products: []Product{
					{
						ID: "pkg:oci/example@sha256:abc",
					},
				},
				Status: StatusNotAffected,
			},
		},
	}
}
