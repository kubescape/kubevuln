package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// VEXStatement represents a normalized vulnerability triage statement.
type VEXStatement struct {
	CVE           string    `json:"cve"`
	Status        string    `json:"status"` // "not_affected" | "fixed" | "under_investigation" | "affected"
	Justification string    `json:"justification,omitempty"`
	SourceURL     string    `json:"sourceUrl"`
	StatementRef  string    `json:"statementRef"`
	ProductPURL   string    `json:"productPurl"`
	Timestamp     time.Time `json:"timestamp"`
}

// VEXParser defines the interface for parsing vendor VEX feeds in a streaming fashion.
type VEXParser interface {
	Parse(r io.Reader, emit func(VEXStatement) error) error
}

// skipValue skips a JSON value in a stream without materializing it.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		if delim == '{' || delim == '[' {
			depth := 1
			for depth > 0 {
				t, err := dec.Token()
				if err != nil {
					return err
				}
				if d, ok := t.(json.Delim); ok {
					if d == '{' || d == '[' {
						depth++
					} else if d == '}' || d == ']' {
						depth--
					}
				}
			}
		}
	}
	return nil
}

// scanRootObject iterates over a JSON object's keys and delegates to handlers.
func scanRootObject(dec *json.Decoder, handlers map[string]func(*json.Decoder) error) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected JSON object start, got %v", t)
	}

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %v", keyToken)
		}

		if handler, exists := handlers[key]; exists {
			if err := handler(dec); err != nil {
				return err
			}
		} else {
			if err := skipValue(dec); err != nil {
				return err
			}
		}
	}

	// Read closing brace
	_, err = dec.Token()
	return err
}

// OpenVEXStreamParser parses OpenVEX JSON documents using streaming tokens.
type OpenVEXStreamParser struct {
	SourceURL string
}

func (p *OpenVEXStreamParser) Parse(r io.Reader, emit func(VEXStatement) error) error {
	dec := json.NewDecoder(r)

	var docTimestamp time.Time
	var bufferedStatements []VEXStatement

	handlers := map[string]func(*json.Decoder) error{
		"timestamp": func(d *json.Decoder) error {
			var tsStr string
			if err := d.Decode(&tsStr); err == nil {
				if parsedTs, err := time.Parse(time.RFC3339, tsStr); err == nil {
					docTimestamp = parsedTs
				}
			}
			return nil
		},
		"statements": func(d *json.Decoder) error {
			t, err := d.Token()
			if err != nil {
				return err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '[' {
				return fmt.Errorf("expected statements array start, got %v", t)
			}

			statementIdx := 0
			for d.More() {
				var rawStmt struct {
					Vulnerability struct {
						Name string `json:"name"`
					} `json:"vulnerability"`
					Status        string            `json:"status"`
					Justification string            `json:"justification"`
					Products      []json.RawMessage `json:"products"`
				}
				if err := d.Decode(&rawStmt); err != nil {
					return err
				}

				for _, prodRaw := range rawStmt.Products {
					prodStr := string(prodRaw)
					var purl string
					if strings.HasPrefix(prodStr, `"`) {
						var s string
						if err := json.Unmarshal(prodRaw, &s); err == nil {
							purl = s
						}
					} else if strings.HasPrefix(prodStr, `{`) {
						var obj struct {
							ID string `json:"@id"`
						}
						if err := json.Unmarshal(prodRaw, &obj); err == nil && obj.ID != "" {
							purl = obj.ID
						} else {
							// skip objects without @id
							continue
						}
					} else {
						continue
					}

					stmt := VEXStatement{
						CVE:           rawStmt.Vulnerability.Name,
						Status:        rawStmt.Status,
						Justification: rawStmt.Justification,
						SourceURL:     p.SourceURL,
						StatementRef:  fmt.Sprintf("%s/statement/%d", p.SourceURL, statementIdx),
						ProductPURL:   purl,
					}
					bufferedStatements = append(bufferedStatements, stmt)
				}
				statementIdx++
			}

			// Read closing bracket of statements array
			_, err = d.Token()
			return err
		},
	}

	if err := scanRootObject(dec, handlers); err != nil {
		return err
	}

	if docTimestamp.IsZero() {
		docTimestamp = time.Now()
	}

	for i := range bufferedStatements {
		bufferedStatements[i].Timestamp = docTimestamp
		if err := emit(bufferedStatements[i]); err != nil {
			return err
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

	var docTimestamp time.Time
	var bufferedStatements []VEXStatement
	productMap := make(map[string]string) // product_id -> PURL

	// Helper for parsing branches
	var parseBranches func(branches []json.RawMessage)
	parseBranches = func(branches []json.RawMessage) {
		for _, bRaw := range branches {
			var b struct {
				Product struct {
					ProductID string `json:"product_id"`
					ProductIdentificationHelper struct {
						PURL string `json:"purl"`
					} `json:"product_identification_helper"`
				} `json:"product"`
				Branches []json.RawMessage `json:"branches"`
			}
			if err := json.Unmarshal(bRaw, &b); err != nil {
				continue
			}
			if b.Product.ProductID != "" && b.Product.ProductIdentificationHelper.PURL != "" {
				productMap[b.Product.ProductID] = b.Product.ProductIdentificationHelper.PURL
			}
			if len(b.Branches) > 0 {
				parseBranches(b.Branches)
			}
		}
	}

	handlers := map[string]func(*json.Decoder) error{
		"document": func(d *json.Decoder) error {
			var doc struct {
				Tracking struct {
					InitialReleaseDate string `json:"initial_release_date"`
				} `json:"tracking"`
			}
			if err := d.Decode(&doc); err == nil {
				if parsedTs, err := time.Parse(time.RFC3339, doc.Tracking.InitialReleaseDate); err == nil {
					docTimestamp = parsedTs
				}
			}
			return nil
		},
		"product_tree": func(d *json.Decoder) error {
			var pt struct {
				FullProductNames []struct {
					ProductID string `json:"product_id"`
					ProductIdentificationHelper struct {
						PURL string `json:"purl"`
					} `json:"product_identification_helper"`
				} `json:"full_product_names"`
				Branches []json.RawMessage `json:"branches"`
			}
			if err := d.Decode(&pt); err != nil {
				return err
			}
			for _, fpn := range pt.FullProductNames {
				if fpn.ProductID != "" && fpn.ProductIdentificationHelper.PURL != "" {
					productMap[fpn.ProductID] = fpn.ProductIdentificationHelper.PURL
				}
			}
			if len(pt.Branches) > 0 {
				parseBranches(pt.Branches)
			}
			return nil
		},
		"vulnerabilities": func(d *json.Decoder) error {
			t, err := d.Token()
			if err != nil {
				return err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '[' {
				return fmt.Errorf("expected vulnerabilities array start, got %v", t)
			}

			vulnIdx := 0
			for d.More() {
				var rawVuln struct {
					CVE           string `json:"cve"`
					ProductStatus struct {
						KnownNotAffected []string `json:"known_not_affected"`
						Fixed            []string `json:"fixed"`
					} `json:"product_status"`
				}
				if err := d.Decode(&rawVuln); err != nil {
					return err
				}

				if rawVuln.CVE != "" {
					// Handle known_not_affected
					for _, prodID := range rawVuln.ProductStatus.KnownNotAffected {
						stmt := VEXStatement{
							CVE:          rawVuln.CVE,
							Status:       "not_affected",
							SourceURL:    p.SourceURL,
							StatementRef: fmt.Sprintf("%s/vuln/%d/not_affected/%s", p.SourceURL, vulnIdx, prodID),
							ProductPURL:  prodID, // Will be resolved to PURL later
						}
						bufferedStatements = append(bufferedStatements, stmt)
					}
					// Handle fixed
					for _, prodID := range rawVuln.ProductStatus.Fixed {
						stmt := VEXStatement{
							CVE:          rawVuln.CVE,
							Status:       "fixed",
							SourceURL:    p.SourceURL,
							StatementRef: fmt.Sprintf("%s/vuln/%d/fixed/%s", p.SourceURL, vulnIdx, prodID),
							ProductPURL:  prodID, // Will be resolved to PURL later
						}
						bufferedStatements = append(bufferedStatements, stmt)
					}
				}
				vulnIdx++
			}
			_, err = d.Token()
			return err
		},
	}

	if err := scanRootObject(dec, handlers); err != nil {
		return err
	}

	if docTimestamp.IsZero() {
		docTimestamp = time.Now()
	}

	for i := range bufferedStatements {
		// Resolve productID to PURL
		if purl, ok := productMap[bufferedStatements[i].ProductPURL]; ok && purl != "" {
			bufferedStatements[i].ProductPURL = purl
		} else {
			// Skip unresolved products
			continue
		}

		if bufferedStatements[i].ProductPURL == "" {
			continue // Never emit an empty ProductPURL
		}

		bufferedStatements[i].Timestamp = docTimestamp
		if err := emit(bufferedStatements[i]); err != nil {
			return err
		}
	}

	return nil
}
