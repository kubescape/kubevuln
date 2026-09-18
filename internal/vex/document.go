package vex

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

type Vulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

type Product struct {
	ID string `json:"id"`
}

func Parse(data []byte) (*Document, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("VEX document is empty")
	}

	var document Document

	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode VEX document: %w", err)
	}

	if err := Validate(&document); err != nil {
		return nil, err
	}

	return &document, nil
}

func Validate(document *Document) error {
	if document == nil {
		return fmt.Errorf("VEX document is nil")
	}

	if strings.TrimSpace(document.Context) == "" {
		return fmt.Errorf("VEX document context is required")
	}

	if !isValidURL(document.Context) {
		return fmt.Errorf("VEX document context must be a valid URL")
	}

	if strings.TrimSpace(document.ID) == "" {
		return fmt.Errorf("VEX document id is required")
	}

	if !isValidURL(document.ID) {
		return fmt.Errorf("VEX document id must be a valid URL")
	}

	if strings.TrimSpace(document.Author) == "" {
		return fmt.Errorf("VEX document author is required")
	}

	if strings.TrimSpace(document.Timestamp) == "" {
		return fmt.Errorf("VEX document timestamp is required")
	}

	if _, err := time.Parse(time.RFC3339, document.Timestamp); err != nil {
		return fmt.Errorf("invalid VEX timestamp: %w", err)
	}

	if document.Version < 1 {
		return fmt.Errorf("VEX document version must be greater than zero")
	}

	if len(document.Statements) == 0 {
		return fmt.Errorf("VEX document must contain at least one statement")
	}

	for index, statement := range document.Statements {
		if err := validateStatement(statement); err != nil {
			return fmt.Errorf("invalid statement at index %d: %w", index, err)
		}
	}

	return nil
}

func validateStatement(statement Statement) error {
	if strings.TrimSpace(statement.Vulnerability.ID) == "" {
		return fmt.Errorf("vulnerability id is required")
	}

	if len(statement.Products) == 0 {
		return fmt.Errorf("at least one product is required")
	}

	for index, product := range statement.Products {
		if strings.TrimSpace(product.ID) == "" {
			return fmt.Errorf("product id is required at index %d", index)
		}
	}

	switch statement.Status {
	case StatusNotAffected,
		StatusAffected,
		StatusFixed,
		StatusUnderInvestigation:
		return nil

	default:
		return fmt.Errorf("unsupported status %q", statement.Status)
	}
}

func isValidURL(value string) bool {
	parsedURL, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil {
		return false
	}

	return parsedURL.Scheme != "" && parsedURL.Host != ""
}
