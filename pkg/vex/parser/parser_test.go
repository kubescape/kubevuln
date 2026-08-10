package parser

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenVEXStreamParser(t *testing.T) {
	payload := `{
		"timestamp": "2026-08-10T12:00:00Z",
		"statements": [
			{
				"vulnerability": {
					"name": "CVE-2026-9999"
				},
				"status": "not_affected",
				"justification": "component_not_present",
				"products": [
					"pkg:alpine/openssl@3.0.2"
				]
			}
		]
	}`

	parser := &OpenVEXStreamParser{SourceURL: "http://example.com/feed.vex"}
	var results []VEXStatement

	err := parser.Parse(strings.NewReader(payload), func(stmt VEXStatement) error {
		results = append(results, stmt)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "CVE-2026-9999", results[0].CVE)
	assert.Equal(t, "not_affected", results[0].Status)
	assert.Equal(t, "component_not_present", results[0].Justification)
	assert.Equal(t, "pkg:alpine/openssl@3.0.2", results[0].ProductPURL)
	assert.Equal(t, "http://example.com/feed.vex/statement/0", results[0].StatementRef)
	assert.Equal(t, "2026-08-10T12:00:00Z", results[0].Timestamp.Format(time.RFC3339))
}

func TestCSAFStreamParser(t *testing.T) {
	payload := `{
		"document": {
			"tracking": {
				"initial_release_date": "2026-08-10T15:00:00Z"
			}
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2026-8888",
				"product_status": {
					"known_not_affected": [
						"pkg:rhel/openssl@3.0.1"
					],
					"fixed": [
						"pkg:rhel/openssl@3.0.2"
					]
				}
			}
		]
	}`

	parser := &CSAFStreamParser{SourceURL: "http://example.com/csaf"}
	var results []VEXStatement

	err := parser.Parse(strings.NewReader(payload), func(stmt VEXStatement) error {
		results = append(results, stmt)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "CVE-2026-8888", results[0].CVE)
	assert.Equal(t, "not_affected", results[0].Status)
	assert.Equal(t, "pkg:rhel/openssl@3.0.1", results[0].ProductPURL)
	assert.Equal(t, "http://example.com/csaf/vuln/0/not_affected/pkg:rhel/openssl@3.0.1", results[0].StatementRef)

	assert.Equal(t, "CVE-2026-8888", results[1].CVE)
	assert.Equal(t, "fixed", results[1].Status)
	assert.Equal(t, "pkg:rhel/openssl@3.0.2", results[1].ProductPURL)
	assert.Equal(t, "http://example.com/csaf/vuln/0/fixed/pkg:rhel/openssl@3.0.2", results[1].StatementRef)
}
