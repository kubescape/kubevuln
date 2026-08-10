package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// VEXStatement represents a normalized vulnerability triage statement.
type VEXStatement struct {
	CVE           string    `json:"cve"`
	Status        string    `json:"status"` // "not_affected" | "fixed" | "under_investigation" | "affected"
	Justification string    `json:"justification,omitempty"`
	StatementRef  string    `json:"statementRef"`
	ProductPURL   string    `json:"productPurl"`
	Timestamp     time.Time `json:"timestamp"`
}

// VEXParser defines the interface for parsing vendor VEX feeds in a streaming fashion.
type VEXParser interface {
	Parse(r io.Reader, emit func(VEXStatement) error) error
}

// OpenVEXStreamParser parses OpenVEX JSON documents using streaming tokens.
type OpenVEXStreamParser struct {
	SourceURL string
}

func (p *OpenVEXStreamParser) Parse(r io.Reader, emit func(VEXStatement) error) error {
	dec := json.NewDecoder(r)

	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected JSON object start, got %v", t)
	}

	docTimestamp := time.Now()

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			continue
		}

		switch key {
		case "timestamp":
			var tsStr string
			if err := dec.Decode(&tsStr); err == nil {
				if parsedTs, err := time.Parse(time.RFC3339, tsStr); err == nil {
					docTimestamp = parsedTs
				}
			}
		case "statements":
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '[' {
				return fmt.Errorf("expected statements array start, got %v", t)
			}

			statementIdx := 0
			for dec.More() {
				var rawStmt struct {
					Vulnerability struct {
						Name string `json:"name"`
					} `json:"vulnerability"`
					Status        string   `json:"status"`
					Justification string   `json:"justification"`
					Products      []string `json:"products"`
				}
				if err := dec.Decode(&rawStmt); err != nil {
					return err
				}

				for _, prod := range rawStmt.Products {
					stmt := VEXStatement{
						CVE:           rawStmt.Vulnerability.Name,
						Status:        rawStmt.Status,
						Justification: rawStmt.Justification,
						StatementRef:  fmt.Sprintf("%s/statement/%d", p.SourceURL, statementIdx),
						ProductPURL:   prod,
						Timestamp:     docTimestamp,
					}
					if err := emit(stmt); err != nil {
						return err
					}
				}
				statementIdx++
			}

			// Read closing bracket of statements array
			if _, err := dec.Token(); err != nil {
				return err
			}
		default:
			// Skip other root properties
			var skip interface{}
			if err := dec.Decode(&skip); err != nil {
				return err
			}
		}
	}

	return nil
}

// CSAFStreamParser parses CSAF JSON documents.
type CSAFStreamParser struct {
	SourceURL string
}

func (p *CSAFStreamParser) Parse(r io.Reader, emit func(VEXStatement) error) error {
	dec := json.NewDecoder(r)

	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected JSON object start, got %v", t)
	}

	docTimestamp := time.Now()

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			continue
		}

		switch key {
		case "document":
			var doc struct {
				Tracking struct {
					InitialReleaseDate string `json:"initial_release_date"`
				} `json:"tracking"`
			}
			if err := dec.Decode(&doc); err == nil {
				if parsedTs, err := time.Parse(time.RFC3339, doc.Tracking.InitialReleaseDate); err == nil {
					docTimestamp = parsedTs
				}
			}
		case "vulnerabilities":
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '[' {
				return fmt.Errorf("expected vulnerabilities array start, got %v", t)
			}

			vulnIdx := 0
			for dec.More() {
				var rawVuln struct {
					CVE           string `json:"cve"`
					ProductStatus struct {
						KnownNotAffected []string `json:"known_not_affected"`
						Fixed            []string `json:"fixed"`
					} `json:"product_status"`
				}
				if err := dec.Decode(&rawVuln); err != nil {
					return err
				}

				if rawVuln.CVE != "" {
					// Handle known_not_affected
					for _, prodID := range rawVuln.ProductStatus.KnownNotAffected {
						stmt := VEXStatement{
							CVE:          rawVuln.CVE,
							Status:       "not_affected",
							StatementRef: fmt.Sprintf("%s/vuln/%d/not_affected/%s", p.SourceURL, vulnIdx, prodID),
							ProductPURL:  prodID, // Maps to package identifier
							Timestamp:    docTimestamp,
						}
						if err := emit(stmt); err != nil {
							return err
						}
					}
					// Handle fixed
					for _, prodID := range rawVuln.ProductStatus.Fixed {
						stmt := VEXStatement{
							CVE:          rawVuln.CVE,
							Status:       "fixed",
							StatementRef: fmt.Sprintf("%s/vuln/%d/fixed/%s", p.SourceURL, vulnIdx, prodID),
							ProductPURL:  prodID,
							Timestamp:    docTimestamp,
						}
						if err := emit(stmt); err != nil {
							return err
						}
					}
				}
				vulnIdx++
			}

			// Read closing bracket of vulnerabilities array
			if _, err := dec.Token(); err != nil {
				return err
			}
		default:
			// Skip other properties
			var skip interface{}
			if err := dec.Decode(&skip); err != nil {
				return err
			}
		}
	}

	return nil
}
